"""
Pentest Mission Control - API Routes
=====================================

Flask routes for the v3.0 conversational interface.
Connects the chat engine to the web dashboard.

SECURITY: All routes require API key authentication via @require_api_key decorator.
"""

import logging
import asyncio
import hmac as hmac_module
from flask import Blueprint, request, jsonify, Response, stream_with_context
from functools import wraps

from .chat_engine import get_chat_engine, QuickActions
from .llm_connector import get_llm_connector
from .tool_registry import get_tool_registry

logger = logging.getLogger(__name__)

# Create Blueprint
api_v3 = Blueprint('api_v3', __name__, url_prefix='/api')

# =============================================================================
# Authentication Decorator (matches app.py implementation)
# =============================================================================

_api_key = None  # Cached API key from config

def _get_api_key():
    """Get API key from config (cached)"""
    global _api_key
    if _api_key is None:
        try:
            from config_manager import get_config
            config = get_config()
            _api_key = config.get_api_key() or ''
        except Exception:
            _api_key = ''
    return _api_key

def require_api_key(f):
    """
    Decorator to require API key authentication for v3 routes.
    Uses constant-time comparison to prevent timing attacks.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = _get_api_key()

        # If no API key configured, allow access (development mode)
        if not api_key:
            return f(*args, **kwargs)

        # Check for API key in header (preferred) or query param (fallback)
        provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')

        if not provided_key:
            return jsonify({
                'success': False,
                'error': 'API key required. Provide via X-API-Key header.'
            }), 401

        # Constant-time comparison to prevent timing attacks (CWE-208)
        if not hmac_module.compare_digest(provided_key, api_key):
            logger.warning(f"Invalid API key attempt from {request.remote_addr}")
            return jsonify({
                'success': False,
                'error': 'Invalid API key'
            }), 403

        return f(*args, **kwargs)
    return decorated

def clear_api_key_cache():
    """Clear cached API key (call when key changes)"""
    global _api_key
    _api_key = None


def async_route(f):
    """Decorator to run async functions in Flask"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(f(*args, **kwargs))
        finally:
            loop.close()
    return wrapper


# =============================================================================
# LLM Configuration Routes
# =============================================================================

@api_v3.route('/llm/status', methods=['GET'])
@require_api_key
def llm_status():
    """Get LLM configuration status"""
    try:
        connector = get_llm_connector()
        status = connector.get_status()
        return jsonify({
            'success': True,
            **status
        })
    except Exception as e:
        logger.error(f"LLM status error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/llm/configure', methods=['POST'])
@require_api_key
def llm_configure():
    """Configure LLM provider"""
    try:
        data = request.get_json() or {}
        connector = get_llm_connector()

        success = connector.configure(
            provider=data.get('provider', 'claude'),
            api_key=data.get('api_key'),
            model=data.get('model'),
            base_url=data.get('base_url')
        )

        if success:
            return jsonify({
                'success': True,
                'message': f"Configured {data.get('provider', 'claude')}",
                'status': connector.get_status()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to configure LLM. Check API key and provider settings.'
            }), 400

    except Exception as e:
        logger.error(f"LLM configure error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/llm/providers', methods=['GET'])
@require_api_key
def llm_providers():
    """List available LLM providers"""
    return jsonify({
        'success': True,
        'providers': [
            {'id': 'claude', 'name': 'Anthropic Claude', 'default_model': 'claude-sonnet-4-20250514'},
            {'id': 'openai', 'name': 'OpenAI GPT', 'default_model': 'gpt-4o'},
            {'id': 'openrouter', 'name': 'OpenRouter', 'default_model': 'anthropic/claude-sonnet-4-20250514'},
            {'id': 'ollama', 'name': 'Ollama (Local)', 'default_model': 'llama3.1'},
            {'id': 'lm_studio', 'name': 'LM Studio (Local)', 'default_model': 'local-model'},
        ]
    })


# =============================================================================
# Chat Routes
# =============================================================================

@api_v3.route('/chat', methods=['POST'])
@require_api_key
@async_route
async def chat():
    """Send a message and get response"""
    try:
        data = request.get_json() or {}
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        engine = get_chat_engine()

        # Check if LLM is configured
        if not engine.is_ready():
            return jsonify({
                'success': False,
                'error': 'LLM not configured. Please configure an LLM provider first.'
            }), 400

        # Set target if provided
        target = data.get('target')
        if target and target != engine.context.target:
            engine.set_target(target)

        # Get response (non-streaming)
        response = await engine.chat(message, stream=False)

        # Get entities and findings
        entities = engine.get_entities()
        findings = engine.get_findings()

        return jsonify({
            'success': True,
            'response': response,
            'entities': entities[-20:],  # Last 20 entities
            'findings': findings[-10:],  # Last 10 findings
            'tool_calls': engine.history[-1].tool_calls if engine.history else []
        })

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/chat/stream', methods=['POST'])
@require_api_key
@async_route
async def chat_stream():
    """Stream chat response"""
    try:
        data = request.get_json() or {}
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        engine = get_chat_engine()

        if not engine.is_ready():
            return jsonify({
                'success': False,
                'error': 'LLM not configured'
            }), 400

        # Set target if provided
        target = data.get('target')
        if target and target != engine.context.target:
            engine.set_target(target)

        def generate():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def stream():
                async for chunk in engine.chat(message, stream=True):
                    yield f"data: {chunk}\n\n"
                yield "data: [DONE]\n\n"

            for chunk in loop.run_until_complete(stream()):
                yield chunk

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream'
        )

    except Exception as e:
        logger.error(f"Chat stream error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/chat/history', methods=['GET'])
@require_api_key
def chat_history():
    """Get conversation history"""
    try:
        engine = get_chat_engine()
        return jsonify({
            'success': True,
            'history': engine.get_history(),
            'target': engine.context.target,
            'entities_count': len(engine.context.entities),
            'findings_count': len(engine.context.findings)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/chat/clear', methods=['POST'])
@require_api_key
def chat_clear():
    """Clear conversation history"""
    try:
        engine = get_chat_engine()
        engine.clear_history()
        return jsonify({'success': True, 'message': 'History cleared'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/chat/reset', methods=['POST'])
@require_api_key
def chat_reset():
    """Reset entire session"""
    try:
        engine = get_chat_engine()
        engine.reset_context()
        return jsonify({'success': True, 'message': 'Session reset'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/chat/export', methods=['GET'])
@require_api_key
def chat_export():
    """Export session data"""
    try:
        engine = get_chat_engine()
        return jsonify({
            'success': True,
            'session': engine.export_session()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Quick Actions
# =============================================================================

@api_v3.route('/quick-actions', methods=['GET'])
@require_api_key
def quick_actions():
    """Get available quick actions"""
    return jsonify({
        'success': True,
        'actions': [
            {'id': 'recon', 'name': 'Full Recon', 'description': 'Comprehensive reconnaissance'},
            {'id': 'vuln', 'name': 'Vulnerability Scan', 'description': 'Nuclei CVE and misconfig scanning'},
            {'id': 'js', 'name': 'JS Analysis', 'description': 'Extract and analyze JavaScript'},
            {'id': 'binary', 'name': 'Binary Analysis', 'description': 'Analyze executable files'},
            {'id': 'process', 'name': 'Process Analysis', 'description': 'Analyze running processes'},
        ]
    })


@api_v3.route('/quick-actions/<action_id>', methods=['GET'])
@require_api_key
def quick_action_prompt(action_id):
    """Get prompt for a quick action"""
    try:
        engine = get_chat_engine()
        target = engine.context.target or 'TARGET'

        prompts = {
            'recon': QuickActions.full_recon(target),
            'vuln': QuickActions.vuln_scan(target),
            'js': QuickActions.js_analysis(target),
            'binary': QuickActions.binary_analysis('/path/to/binary'),
            'process': QuickActions.process_analysis('target_process'),
        }

        if action_id not in prompts:
            return jsonify({'success': False, 'error': 'Unknown action'}), 404

        return jsonify({
            'success': True,
            'action': action_id,
            'prompt': prompts[action_id]
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Tool Routes
# =============================================================================

@api_v3.route('/tools', methods=['GET'])
@require_api_key
def list_tools():
    """List all available tools"""
    try:
        registry = get_tool_registry()
        return jsonify({
            'success': True,
            'tools': registry.list_tools()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/tools/available', methods=['GET'])
@require_api_key
def available_tools():
    """List only available (installed) tools"""
    try:
        registry = get_tool_registry()
        return jsonify({
            'success': True,
            'tools': registry.list_available()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/tools/execute', methods=['POST'])
@require_api_key
@async_route
async def execute_tool():
    """Execute a specific tool directly"""
    try:
        data = request.get_json() or {}
        tool_name = data.get('tool')
        method = data.get('method')
        params = data.get('params', {})

        if not tool_name or not method:
            return jsonify({'success': False, 'error': 'tool and method are required'}), 400

        registry = get_tool_registry()
        result = await registry.execute(tool_name, method, **params)

        return jsonify({
            'success': result.success,
            'tool': result.tool,
            'method': result.method,
            'output': result.output,
            'error': result.error,
            'duration': result.duration,
            'entities': result.entities
        })

    except Exception as e:
        logger.error(f"Tool execute error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Entity/Knowledge Graph Routes
# =============================================================================

@api_v3.route('/entities', methods=['GET'])
@require_api_key
def list_entities():
    """List discovered entities"""
    try:
        engine = get_chat_engine()
        entities = engine.get_entities()

        # Optional filtering
        entity_type = request.args.get('type')
        if entity_type:
            entities = [e for e in entities if e.get('type') == entity_type]

        return jsonify({
            'success': True,
            'entities': entities,
            'total': len(entities)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/entities/types', methods=['GET'])
@require_api_key
def entity_types():
    """Get entity type summary"""
    try:
        engine = get_chat_engine()
        entities = engine.get_entities()

        type_counts = {}
        for e in entities:
            t = e.get('type', 'unknown')
            type_counts[t] = type_counts.get(t, 0) + 1

        return jsonify({
            'success': True,
            'types': type_counts
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Findings Routes
# =============================================================================

@api_v3.route('/findings', methods=['GET'])
@require_api_key
def list_findings():
    """List security findings"""
    try:
        engine = get_chat_engine()
        findings = engine.get_findings()

        # Optional severity filter
        severity = request.args.get('severity')
        if severity:
            findings = [f for f in findings if f.get('severity') == severity]

        return jsonify({
            'success': True,
            'findings': findings,
            'total': len(findings)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/findings/summary', methods=['GET'])
@require_api_key
def findings_summary():
    """Get findings summary by severity"""
    try:
        engine = get_chat_engine()
        findings = engine.get_findings()

        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for f in findings:
            sev = f.get('severity', 'info').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return jsonify({
            'success': True,
            'summary': severity_counts,
            'total': len(findings)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Target Routes
# =============================================================================

@api_v3.route('/target', methods=['GET'])
@require_api_key
def get_target():
    """Get current target"""
    try:
        engine = get_chat_engine()
        return jsonify({
            'success': True,
            'target': engine.context.target,
            'scope': engine.context.scope
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@api_v3.route('/target', methods=['POST'])
@require_api_key
def set_target():
    """Set current target"""
    try:
        data = request.get_json() or {}
        target = data.get('target')
        scope = data.get('scope')

        if not target:
            return jsonify({'success': False, 'error': 'target is required'}), 400

        engine = get_chat_engine()
        engine.set_target(target, scope)

        return jsonify({
            'success': True,
            'target': engine.context.target,
            'scope': engine.context.scope
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# =============================================================================
# Register Blueprint Function
# =============================================================================

def register_v3_routes(app):
    """Register v3 API routes with Flask app"""
    app.register_blueprint(api_v3)
    logger.info("Registered v3 API routes")


# =============================================================================
# Standalone Test Server
# =============================================================================

if __name__ == '__main__':
    from flask import Flask

    logging.basicConfig(level=logging.DEBUG)

    app = Flask(__name__)
    register_v3_routes(app)

    @app.route('/')
    def index():
        return "Pentest Mission Control v3 API"

    import os
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    host = os.getenv('FLASK_HOST', '127.0.0.1')
    port = int(os.getenv('FLASK_PORT', '5002'))
    print(f"Starting server on http://{host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, debug=debug_mode)
