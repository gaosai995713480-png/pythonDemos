from backend.tripstar.services.llm_service import _extract_chat_content


def test_extract_chat_content_supports_event_stream_chunks():
    content_type = "text/event-stream"
    body = """
data: {"choices":[{"delta":{"role":"assistant","content":"{\\"ok\\""}}]}

data: {"choices":[{"delta":{"content":": true"}}]}

data: {"choices":[{"delta":{"content":", \\"provider\\": \\"grok\\"}"}}]}

data: [DONE]
"""

    assert _extract_chat_content(content_type, body, {}) == '{"ok": true, "provider": "grok"}'
