#!/bin/bash
# Bash script to commit and push all bug fixes
# Run this from the localstack directory

echo "LocalStack Bug Fixes - Git Push Script"
echo "======================================="
echo ""

# Check if we're in a git repository
if [ ! -d ".git" ]; then
    echo "Error: Not in a git repository!"
    exit 1
fi

# Show current status
echo "Current Git Status:"
git status --short

echo ""
echo "Files to be committed:"
echo "  1. localstack-core/localstack/services/stepfunctions/provider.py"
echo "  2. localstack-core/localstack/services/firehose/provider.py"
echo "  3. localstack-core/localstack/services/lambda_/provider.py"
echo "  4. localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py"
echo "  5. localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py"
echo "  6. localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py"
echo "  7. BUG_FIXES_SUMMARY.md"
echo ""

# Ask for confirmation
read -p "Do you want to proceed with committing these changes? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Ask for commit strategy
echo ""
echo "Choose commit strategy:"
echo "  1. Single commit (all fixes together)"
echo "  2. Separate commits (one per bug fix)"
echo "  3. Create new feature branch first"
read -p "Enter choice (1-3): " strategy

# Create branch if option 3
if [ "$strategy" = "3" ]; then
    read -p "Enter branch name (e.g., fix/multiple-service-bugs): " branchName
    echo "Creating and checking out branch: $branchName"
    git checkout -b "$branchName"
    read -p "Now choose commit strategy (1 or 2): " strategy
fi

if [ "$strategy" = "1" ]; then
    # Single commit
    echo ""
    echo "Creating single commit..."
    
    git add localstack-core/localstack/services/stepfunctions/provider.py
    git add localstack-core/localstack/services/firehose/provider.py
    git add localstack-core/localstack/services/lambda_/provider.py
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py
    git add localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py
    git add BUG_FIXES_SUMMARY.md
    
    git commit -m "fix: resolve 4 critical bugs across Lambda, StepFunctions, and Firehose

- fix(lambda): make create_alias idempotent for CDK redeployments (#13351)
- fix(stepfunctions): enhance InvalidArn error messages with details (#13315)
- fix(firehose): implement S3 CompressionFormat support (GZIP/ZIP/Snappy) (#13301)
- fix(stepfunctions): enable variable interpolation in TestState API (#13215)

All fixes maintain backward compatibility and follow LocalStack conventions.
See BUG_FIXES_SUMMARY.md for detailed documentation."
    
    echo "Commit created successfully!"
    
elif [ "$strategy" = "2" ]; then
    # Separate commits
    echo ""
    echo "Creating separate commits..."
    
    # Commit 1: Lambda
    git add localstack-core/localstack/services/lambda_/provider.py
    git commit -m "fix(lambda): make create_alias idempotent for CDK redeployments (#13351)

When using CDK with Lambda versions, redeploying would fail with 'Alias 
already exists' error. Now returns existing alias if configuration matches,
enabling idempotent CDK deployments."
    echo "  ✓ Lambda fix committed"
    
    # Commit 2: StepFunctions InvalidArn
    git add localstack-core/localstack/services/stepfunctions/provider.py
    git commit -m "fix(stepfunctions): enhance InvalidArn error messages with details (#13315)

InvalidArn exceptions now communicate which part of the ARN is incorrect
(service, resource type, format), making debugging significantly easier."
    echo "  ✓ StepFunctions InvalidArn fix committed"
    
    # Commit 3: Firehose
    git add localstack-core/localstack/services/firehose/provider.py
    git commit -m "fix(firehose): implement S3 CompressionFormat support (#13301)

Adds support for GZIP, ZIP, and Snappy compression when writing to S3.
Automatically appends correct file extensions based on compression format."
    echo "  ✓ Firehose compression fix committed"
    
    # Commit 4: TestState
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py
    git add localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py
    git commit -m "fix(stepfunctions): enable variable interpolation in TestState API (#13215)

The variables parameter was accepted but ignored. Now properly initializes
VariableStore and passes variables through the execution chain."
    echo "  ✓ TestState variables fix committed"
    
    # Commit 5: Documentation
    git add BUG_FIXES_SUMMARY.md
    git commit -m "docs: add comprehensive bug fixes documentation

Documents all 4 bug fixes with problem descriptions, solutions, 
testing commands, and code examples."
    echo "  ✓ Documentation committed"
    
    echo ""
    echo "All commits created successfully!"
else
    echo "Invalid choice. Aborted."
    exit 1
fi

# Show log
echo ""
echo "Recent commits:"
git log --oneline -5

# Ask about pushing
echo ""
read -p "Do you want to push to remote now? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Enter remote name (default: origin): " remote
    remote=${remote:-origin}
    
    branch=$(git branch --show-current)
    echo ""
    echo "Pushing to $remote/$branch..."
    git push -u "$remote" "$branch"
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✓ Successfully pushed to remote!"
        echo ""
        echo "Next steps:"
        echo "  1. Go to https://github.com/localstack/localstack"
        echo "  2. Create a Pull Request from your branch"
        echo "  3. Reference issues: #13351, #13315, #13301, #13215"
        echo "  4. Include BUG_FIXES_SUMMARY.md in PR description"
    else
        echo ""
        echo "Push failed. Please check the error above."
    fi
else
    echo ""
    echo "Commits created but not pushed."
    echo "To push later, run: git push -u origin $(git branch --show-current)"
fi

echo ""
echo "Done!"
