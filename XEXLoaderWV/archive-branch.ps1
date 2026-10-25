#!/usr/bin/env pwsh

param(
    [Parameter(Position = 0)]
    [string]$Category = "archive/note-finished"
)

$ErrorActionPreference = "Stop"

function Invoke-Git {
    param(
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$Args
    )

    & git @Args

    if ($LASTEXITCODE -ne 0) {
        throw "git $($Args -join ' ') failed with exit code $LASTEXITCODE."
    }
}

# Verify we're inside a Git repository.
$repoRoot = git rev-parse --show-toplevel 2>$null

if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repoRoot)) {
    throw "Not inside a Git repository."
}

$currentBranch = git branch --show-current

if ([string]::IsNullOrWhiteSpace($currentBranch)) {
    throw "Detached HEAD. Checkout the branch you want to move first."
}

# Normal working branches live under note-working/.
if (-not $currentBranch.StartsWith("note-working/")) {
    throw "Refusing to move '$currentBranch'. Expected a branch under note-working/."
}

$branchName = $currentBranch.Substring("note-working/".Length)

if ([string]::IsNullOrWhiteSpace($branchName)) {
    throw "Unable to determine destination branch name."
}

# Normalize the requested category.
$Category = $Category.Trim().Trim("/")

if ([string]::IsNullOrWhiteSpace($Category)) {
    throw "Category cannot be empty."
}

# Bare category names are assumed to live under archive/.
# Examples:
#   backup               -> archive/backup
#   note-finished        -> archive/note-finished
#   archive/backup       -> archive/backup
#   somewhere/else       -> somewhere/else
if (-not $Category.Contains("/")) {
    $Category = "archive/$Category"
}

$destinationBranch = "$Category/$branchName"

# Ask Git itself whether this is a legal branch name.
git check-ref-format --branch $destinationBranch *> $null

if ($LASTEXITCODE -ne 0) {
    throw "'$destinationBranch' is not a valid Git branch name."
}

# Don't move uncommitted work accidentally.
$workingTree = git status --porcelain

if ($workingTree) {
    throw "Working tree has uncommitted changes. Commit or stash them before moving the branch."
}

# Ensure origin exists.
git remote get-url origin *> $null

if ($LASTEXITCODE -ne 0) {
    throw "Remote 'origin' does not exist."
}

# Refuse to overwrite an existing local destination branch.
git show-ref --verify --quiet "refs/heads/$destinationBranch"

if ($LASTEXITCODE -eq 0) {
    throw "Local branch '$destinationBranch' already exists."
}

# Refuse to overwrite an existing remote destination branch.
git ls-remote --exit-code --heads origin $destinationBranch *> $null

if ($LASTEXITCODE -eq 0) {
    throw "Remote branch '$destinationBranch' already exists."
}

# Fetch to ensure we have the lastest remote state
Invoke-Git fetch

# Pull the current branch to make sure it's up to date before moving it.
Invoke-Git pull --ff-only origin $currentBranch

Write-Host ""
Write-Host "Moving branch:"
Write-Host "  $currentBranch"
Write-Host "    ->"
Write-Host "  $destinationBranch"
Write-Host ""

# Check whether the old remote branch actually exists before changing anything.
git ls-remote --exit-code --heads origin $currentBranch *> $null
$oldRemoteExists = $LASTEXITCODE -eq 0

# Rename the local branch.
Invoke-Git branch -m $destinationBranch

try {
    # Publish the renamed branch and establish its new upstream.
    Invoke-Git push -u origin $destinationBranch
}
catch {
    Write-Warning "Push failed. Renaming local branch back to '$currentBranch'."

    & git branch -m $currentBranch

    throw
}

# Remove the old remote branch once the new one exists safely.
if ($oldRemoteExists) {
    Invoke-Git push origin --delete $currentBranch
}

Write-Host ""
Write-Host "Moved successfully:"
Write-Host "  $destinationBranch"

# After the archive operation is fully complete, return to testing and
# fast-forward it from origin. This keeps the local base current for later
# rebase operations without rewriting any divergent local commits.
Write-Host ""
Write-Host "Switching to testing and pulling origin/testing..."

try {
    git show-ref --verify --quiet "refs/heads/testing"
    $localTestingExists = $LASTEXITCODE -eq 0

    if ($localTestingExists) {
        Invoke-Git switch testing
    }
    else {
        # A fresh clone may not have a local testing branch yet.
        Invoke-Git fetch origin testing
        Invoke-Git switch --track origin/testing
    }

    Invoke-Git pull --ff-only origin testing
}
catch {
    Write-Warning "Archive completed, but testing could not be updated. Resolve the testing branch separately."
    throw
}

Write-Host ""
Write-Host "Local testing is synchronized with origin/testing."
