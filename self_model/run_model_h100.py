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

# --- CONFIGURATION FOR H100 ---

# 1. POINT TO YOUR FP8 MODEL
# Run 'huggingface-cli download neuralmagic/Qwen2.5-Coder-72B-Instruct-FP8 ...' first!
MODEL_PATH = "home/ubuntu/models_weights/qwen-72b-fp8"

# 2. H100 PERFORMANCE SETTINGS
MAX_MODEL_LEN = 100000        # The 100k Context Window
GPU_UTILIZATION = 0.98        # Use 98% of the 94GB VRAM
KV_CACHE_DTYPE = "fp8"        # The secret to fitting 100k tokens
TENSOR_PARALLEL = 1           # Single H100

# Global State
engine = None
tokenizer = None

# --- LIFESPAN MANAGER ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Initializes the engine safely on startup.
    """
    global engine, tokenizer
    
    print(f"--- Loading Tokenizer from {MODEL_PATH}... ---")
    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, trust_remote_code=True)
    except Exception as e:
        print(f"FATAL: Could not load tokenizer from {MODEL_PATH}. Did you download the model?")
        raise e

    print("--- Initializing vLLM Engine (H100/FP8 Mode)... ---")
    
    # Ensure we use the GPU (Clean up any env vars that might force CPU)
    os.environ.pop('VLLM_TARGET_DEVICE', None) 
    
    engine_args = AsyncEngineArgs(
        model=MODEL_PATH,
        max_model_len=MAX_MODEL_LEN,
        # On H100/GPU, vLLM calculates batch sizes automatically based on memory.
        # We generally do NOT need to manually set max_num_batched_tokens here.
        gpu_memory_utilization=GPU_UTILIZATION,
        kv_cache_dtype=KV_CACHE_DTYPE,
        tensor_parallel_size=TENSOR_PARALLEL,
        disable_log_stats=True,    # Keep logs clean
        enforce_eager=False,       # False = Enable CUDA Graphs (Max Speed)
        trust_remote_code=True,
        worker_use_ray=False       # Simple multiprocessing is stable for single-GPU
    )
    
    engine = AsyncLLMEngine.from_engine_args(engine_args)
    print("--- Engine Ready! Serving 72B Model on port 8000... ---")
    
    yield
    
    print("--- Shutting down engine ---")

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

# --- HANDLERS ---
async def models_handler():
    return {
        "object": "list", 
        "data": [{
            "id": "qwen-72b-fp8", 
            "object": "model", 
            "created": int(time.time()), 
            "owned_by": "h100-owner"
        }]
    }

async def chat_handler(request: Request):
    if engine is None: 
        raise HTTPException(status_code=503, detail="Engine initializing...")

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
        temperature=data.get("temperature", 0.6),
        top_p=data.get("top_p", 0.95),
        max_tokens=data.get("max_tokens", 4096), 
        stop=data.get("stop", [])
    )

    request_id = f"chatcmpl-{uuid.uuid4()}"

    if stream:
        async def stream_gen():
            results = engine.generate(prompt, sampling_params, request_id)
            prev_text = ""
            async for output in results:
                curr = output.outputs[0].text
                delta = curr[len(prev_text):]
                prev_text = curr
                if delta: 
                    yield f"data: {json.dumps(create_openai_chunk(request_id, 'qwen-72b-fp8', delta))}\n\n"
            
            yield f"data: {json.dumps(create_openai_chunk(request_id, 'qwen-72b-fp8', '', 'stop'))}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(stream_gen(), media_type="text/event-stream")
    else:
        results = engine.generate(prompt, sampling_params, request_id)
        final_output = None
        async for output in results: 
            final_output = output
        
        full_text = final_output.outputs[0].text
        
        return {
            "id": request_id, 
            "object": "chat.completion", 
            "created": int(time.time()), 
            "model": "qwen-72b-fp8",
            "choices": [{
                "index": 0, 
                "message": {"role": "assistant", "content": full_text}, 
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(final_output.prompt_token_ids), 
                "completion_tokens": len(final_output.outputs[0].token_ids), 
                "total_tokens": 0
            }
        }

# --- ROUTES ---
# Listen on BOTH /v1/chat/completions AND /chat/completions for compatibility
app.add_api_route("/v1/models", models_handler, methods=["GET"])
app.add_api_route("/models", models_handler, methods=["GET"])
app.add_api_route("/v1/chat/completions", chat_handler, methods=["POST"])
app.add_api_route("/chat/completions", chat_handler, methods=["POST"])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)