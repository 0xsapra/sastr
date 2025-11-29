python -m vllm.entrypoints.openai.api_server \
    --model /home/amanistaken/data/upload/self_model/qwen-checkpoint \
    --served-model-name qwen-32b-fp8 \
    --trust-remote-code \
    --kv-cache-dtype fp8 \
    --gpu-memory-utilization 0.95 \
    --max-model-len 32768