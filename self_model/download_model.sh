
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve current working directory
CURRENT_DIR="$(pwd)"

# Compare
if [[ "$SCRIPT_DIR" != "$CURRENT_DIR" ]]; then
    echo "❌ Error: Run this script only from its own directory:"
    echo "   $SCRIPT_DIR"
    exit 1
fi

# Create a folder for local testing
# mkdir -p ./qwen-1.5b

# # Download the 1.5B model (approx 3GB)
# huggingface-cli download Qwen/Qwen2.5-Coder-1.5B-Instruct \
#   --local-dir ./qwen-1.5b \
#   --local-dir-use-symlinks False


mkdir -p ./qwen-7b
huggingface-cli download Qwen/Qwen2.5-Coder-7B-Instruct --local-dir ./qwen-7b --local-dir-use-symlinks False


# # Create the directory
# mkdir -p /home/ubuntu/models_weights/qwen-72b-fp8

# # Download the model weights
huggingface-cli download Qwen/Qwen2.5-Coder-32B-Instruct \
  --local-dir /home/ubuntu/models_weights/qwen-72b-fp8 \
  --local-dir-use-symlinks False

# pip install "huggingface_hub[cli]" vllm fastapi uvicorn transformers

# # 2. Create Directory
# mkdir -p /home/ubuntu/my_models/qwen-72b-fp8

# # 3. Download the Neural Magic FP8 version (Optimized for H100)
# huggingface-cli download neuralmagic/Qwen2.5-Coder-72B-Instruct-FP8 \
#   --local-dir /home/ubuntu/my_models/qwen-72b-fp8 \
#   --local-dir-use-symlinks False

# # 4. Run Server
# python3 inference_server.py