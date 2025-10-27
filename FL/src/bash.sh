#!/bin/bash
for i in {0..281}; do
    echo "Processing policy $i..."
    python3 request_generate.py $i 15 100
done

echo "Done processing all policies!"