#!/bin/bash
# Calculate iteration limit for $4 GPT-4o budget

echo "# 💰 GPT-4o Budget Calculator"
echo "=============================="
echo ""

echo "## GPT-4o Pricing (as of 2024)"
echo "------------------------------"
echo "Input:  $2.50 per 1M tokens"
echo "Output: $10.00 per 1M tokens"
echo ""

echo "## Estimated Token Usage Per Iteration"
echo "--------------------------------------"
echo "Based on previous 120B test (75 iterations, 1.89M tokens):"
echo ""
TOKENS_PER_ITER=$((1892073 / 75))
echo "Average tokens per iteration: $TOKENS_PER_ITER tokens"
echo ""

echo "Assuming 70% input, 30% output (typical for agent):"
INPUT_PER_ITER=$(echo "$TOKENS_PER_ITER * 0.7" | bc | cut -d. -f1)
OUTPUT_PER_ITER=$(echo "$TOKENS_PER_ITER * 0.3" | bc | cut -d. -f1)
echo "  Input:  ~$INPUT_PER_ITER tokens/iter"
echo "  Output: ~$OUTPUT_PER_ITER tokens/iter"
echo ""

echo "## Cost Per Iteration"
echo "--------------------"
INPUT_COST=$(echo "scale=4; $INPUT_PER_ITER * 2.50 / 1000000" | bc)
OUTPUT_COST=$(echo "scale=4; $OUTPUT_PER_ITER * 10.00 / 1000000" | bc)
TOTAL_COST=$(echo "scale=4; $INPUT_COST + $OUTPUT_COST" | bc)
echo "Input cost:  \$$INPUT_COST"
echo "Output cost: \$$OUTPUT_COST"
echo "Total:       \$$TOTAL_COST per iteration"
echo ""

echo "## Iterations for \$4 Budget"
echo "---------------------------"
ITERATIONS=$(echo "scale=0; 4 / $TOTAL_COST" | bc)
echo "Maximum iterations: $ITERATIONS"
echo ""

echo "## Recommendation"
echo "----------------"
SAFE_ITERS=$((ITERATIONS - 5))
echo "Safe limit (with buffer): $SAFE_ITERS iterations"
echo ""
echo "This should be enough for GPT-4o to:"
echo "  1. Run nmap scan"
echo "  2. Discover web app"
echo "  3. Find config files or brute force credentials"
echo "  4. Install MySQL client"
echo "  5. Connect to database"
echo "  6. Extract flags and data"
echo ""

