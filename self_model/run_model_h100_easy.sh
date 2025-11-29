python -m vllm.entrypoints.openai.api_server \
    --model /workspace/upload/self_model/qwen-checkpoint \
    --served-model-name qwen-32b-fp8 \
    --trust-remote-code \
    --kv-cache-dtype fp8 \
    --gpu-memory-utilization 0.90 \
    --max-model-len 32768 \
    --enable-auto-tool-choice \
    --tool-call-parser hermes