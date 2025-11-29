import os
import uuid
import time
import json
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from vllm.engine.arg_utils import AsyncEngineArgs
from vllm.engine.async_llm_engine import AsyncLLMEngine
from vllm.sampling_params import SamplingParams
from transformers import AutoTokenizer

# --- CONFIGURATION ---

# MAC LOCAL PATH
MODEL_PATH = os.path.expanduser("./qwen-1.5b")

# MAC / CPU Specific Settings
MAX_MODEL_LEN = 32768   
GPU_UTILIZATION = 0.60  
KV_CACHE_DTYPE = "auto"
TENSOR_PARALLEL = 1

# Global variables to hold the engine and tokenizer
engine = None
tokenizer = None

# --- LIFESPAN MANAGER (The Fix for Multiprocessing Error) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    This function runs ONLY when the main server starts.
    Child processes spawned by vLLM will NOT run this code.
    """
    global engine, tokenizer
    
    print(f"--- Loading Tokenizer from {MODEL_PATH}... ---")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)

    print("--- Initializing vLLM Engine (Mac/CPU Mode)... ---")
    
    # Force CPU environment variables internally just to be safe
    os.environ['VLLM_TARGET_DEVICE'] = 'cpu'
    
    engine_args = AsyncEngineArgs(
        model=MODEL_PATH,
        max_model_len=MAX_MODEL_LEN,
        max_num_batched_tokens=MAX_MODEL_LEN,
        gpu_memory_utilization=GPU_UTILIZATION,
        kv_cache_dtype=KV_CACHE_DTYPE,
        tensor_parallel_size=TENSOR_PARALLEL,
        disable_log_stats=True,
        enforce_eager=True,
        trust_remote_code=True,
    )
    
    engine = AsyncLLMEngine.from_engine_args(engine_args)
    print("--- Engine Ready! Serving OpenAI-compatible API... ---")
    
    yield
    
    # Cleanup code (if any) goes here
    print("--- Shutting down engine ---")

# Initialize app with the lifespan manager
app = FastAPI(lifespan=lifespan)

# --- UTILS ---
def create_openai_chunk(request_id, model, delta_content, finish_reason=None):
    """Helper to format a streaming chunk exactly like OpenAI"""
    return {
        "id": request_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": {"content": delta_content} if delta_content else {},
                "finish_reason": finish_reason
            }
        ]
    }

# --- ENDPOINTS ---

@app.get("/v1/models")
async def show_models():
    return {
        "object": "list",
        "data": [{
            "id": MODEL_PATH, 
            "object": "model",
            "created": int(time.time()),
            "owned_by": "local-owner"
        }]
    }

@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    # Check if engine is ready
    if engine is None:
        raise HTTPException(status_code=503, detail="Engine not yet initialized")

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON")

    messages = data.get("messages")
    if not messages:
        raise HTTPException(status_code=400, detail="Missing 'messages'")

    stream = data.get("stream", False)
    
    try:
        prompt = tokenizer.apply_chat_template(
            messages, 
            tokenize=False, 
            add_generation_prompt=True
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Template Error: {str(e)}")

    sampling_params = SamplingParams(
        temperature=data.get("temperature", 0.7),
        top_p=data.get("top_p", 1.0),
        max_tokens=data.get("max_tokens", 4096), 
        stop=data.get("stop", [])
    )

    request_id = f"chatcmpl-{uuid.uuid4()}"

    if stream:
        async def stream_generator():
            results_generator = engine.generate(prompt, sampling_params, request_id)
            previous_text = ""
            
            async for request_output in results_generator:
                current_text = request_output.outputs[0].text
                delta = current_text[len(previous_text):]
                previous_text = current_text
                
                if delta:
                    chunk = create_openai_chunk(request_id, MODEL_PATH, delta)
                    yield f"data: {json.dumps(chunk)}\n\n"
            
            final_chunk = create_openai_chunk(request_id, MODEL_PATH, "", finish_reason="stop")
            yield f"data: {json.dumps(final_chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    else:
        results_generator = engine.generate(prompt, sampling_params, request_id)
        final_output = None
        async for request_output in results_generator:
            final_output = request_output
        
        full_text = final_output.outputs[0].text
        
        return {
            "id": request_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": MODEL_PATH,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": full_text
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(final_output.prompt_token_ids),
                "completion_tokens": len(final_output.outputs[0].token_ids),
                "total_tokens": len(final_output.prompt_token_ids) + len(final_output.outputs[0].token_ids)
            }
        }

if __name__ == "__main__":
    # IMPORTANT: Set strict False if relying on global state in this specific way without pickling issues,
    # but the lifespan manager handles the heavy lifting.
    uvicorn.run(app, host="0.0.0.0", port=8000)