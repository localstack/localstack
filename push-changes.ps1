# PowerShell script to commit and push all bug fixes
# Run this from the localstack directory

Write-Host "LocalStack Bug Fixes - Git Push Script" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in a git repository
if (-not (Test-Path ".git")) {
    Write-Host "Error: Not in a git repository!" -ForegroundColor Red
    exit 1
}

# Show current status
Write-Host "Current Git Status:" -ForegroundColor Yellow
git status --short

Write-Host ""
Write-Host "Files to be committed:" -ForegroundColor Yellow
Write-Host "  1. localstack-core/localstack/services/stepfunctions/provider.py" -ForegroundColor Green
Write-Host "  2. localstack-core/localstack/services/firehose/provider.py" -ForegroundColor Green
Write-Host "  3. localstack-core/localstack/services/lambda_/provider.py" -ForegroundColor Green
Write-Host "  4. localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py" -ForegroundColor Green
Write-Host "  5. localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py" -ForegroundColor Green
Write-Host "  6. localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py" -ForegroundColor Green
Write-Host "  7. BUG_FIXES_SUMMARY.md" -ForegroundColor Green
Write-Host ""

# Ask for confirmation
$response = Read-Host "Do you want to proceed with committing these changes? (y/n)"
if ($response -ne 'y') {
    Write-Host "Aborted." -ForegroundColor Yellow
    exit 0
}

# Ask for commit strategy
Write-Host ""
Write-Host "Choose commit strategy:" -ForegroundColor Yellow
Write-Host "  1. Single commit (all fixes together)" -ForegroundColor White
Write-Host "  2. Separate commits (one per bug fix)" -ForegroundColor White
Write-Host "  3. Create new feature branch first" -ForegroundColor White
$strategy = Read-Host "Enter choice (1-3)"

# Create branch if option 3
if ($strategy -eq '3') {
    $branchName = Read-Host "Enter branch name (e.g., fix/multiple-service-bugs)"
    Write-Host "Creating and checking out branch: $branchName" -ForegroundColor Cyan
    git checkout -b $branchName
    $strategy = Read-Host "Now choose commit strategy (1 or 2)"
}

if ($strategy -eq '1') {
    # Single commit
    Write-Host ""
    Write-Host "Creating single commit..." -ForegroundColor Cyan
    
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
    
    Write-Host "Commit created successfully!" -ForegroundColor Green
}
elseif ($strategy -eq '2') {
    # Separate commits
    Write-Host ""
    Write-Host "Creating separate commits..." -ForegroundColor Cyan
    
    # Commit 1: Lambda
    git add localstack-core/localstack/services/lambda_/provider.py
    git commit -m "fix(lambda): make create_alias idempotent for CDK redeployments (#13351)

When using CDK with Lambda versions, redeploying would fail with 'Alias 
already exists' error. Now returns existing alias if configuration matches,
enabling idempotent CDK deployments."
    Write-Host "  ✓ Lambda fix committed" -ForegroundColor Green
    
    # Commit 2: StepFunctions InvalidArn
    git add localstack-core/localstack/services/stepfunctions/provider.py
    git commit -m "fix(stepfunctions): enhance InvalidArn error messages with details (#13315)

InvalidArn exceptions now communicate which part of the ARN is incorrect
(service, resource type, format), making debugging significantly easier."
    Write-Host "  ✓ StepFunctions InvalidArn fix committed" -ForegroundColor Green
    
    # Commit 3: Firehose
    git add localstack-core/localstack/services/firehose/provider.py
    git commit -m "fix(firehose): implement S3 CompressionFormat support (#13301)

Adds support for GZIP, ZIP, and Snappy compression when writing to S3.
Automatically appends correct file extensions based on compression format."
    Write-Host "  ✓ Firehose compression fix committed" -ForegroundColor Green
    
    # Commit 4: TestState
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution.py
    git add localstack-core/localstack/services/stepfunctions/backend/test_state/execution_worker.py
    git add localstack-core/localstack/services/stepfunctions/asl/eval/test_state/environment.py
    git commit -m "fix(stepfunctions): enable variable interpolation in TestState API (#13215)

The variables parameter was accepted but ignored. Now properly initializes
VariableStore and passes variables through the execution chain."
    Write-Host "  ✓ TestState variables fix committed" -ForegroundColor Green
    
    # Commit 5: Documentation
    git add BUG_FIXES_SUMMARY.md
    git commit -m "docs: add comprehensive bug fixes documentation

Documents all 4 bug fixes with problem descriptions, solutions, 
testing commands, and code examples."
    Write-Host "  ✓ Documentation committed" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "All commits created successfully!" -ForegroundColor Green
}
else {
    Write-Host "Invalid choice. Aborted." -ForegroundColor Red
    exit 1
}

# Show log
Write-Host ""
Write-Host "Recent commits:" -ForegroundColor Yellow
git log --oneline -5

# Ask about pushing
Write-Host ""
$push = Read-Host "Do you want to push to remote now? (y/n)"
if ($push -eq 'y') {
    $remote = Read-Host "Enter remote name (default: origin)"
    if ([string]::IsNullOrWhiteSpace($remote)) {
        $remote = "origin"
    }
    
    $branch = git branch --show-current
    Write-Host ""
    Write-Host "Pushing to $remote/$branch..." -ForegroundColor Cyan
    git push -u $remote $branch
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "✓ Successfully pushed to remote!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Go to https://github.com/localstack/localstack" -ForegroundColor White
        Write-Host "  2. Create a Pull Request from your branch" -ForegroundColor White
        Write-Host "  3. Reference issues: #13351, #13315, #13301, #13215" -ForegroundColor White
        Write-Host "  4. Include BUG_FIXES_SUMMARY.md in PR description" -ForegroundColor White
    } else {
        Write-Host ""
        Write-Host "Push failed. Please check the error above." -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "Commits created but not pushed." -ForegroundColor Yellow
    Write-Host "To push later, run: git push -u origin $(git branch --show-current)" -ForegroundColor White
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Cyan
