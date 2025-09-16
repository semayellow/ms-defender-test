#!/bin/bash

# Parameters: SAStoken storageAccountName containerName filePath1 [filePath2 ...]
SAStoken="$1"
storageAccountName="$2"
containerName="$3"
shift 3
filePaths=("$@")

# Redirect all output (stdout and stderr) to the log file
exec > /home/user/Desktop/ANYRUN_FULLlog.txt 2>&1

# Get current date for logging
date=$(date +"%Y-%m-%d %H:%M:%S")

# Output all input variables to console
echo "Input parameters:"
echo "filePath: ${filePaths[*]}"
echo "SAStoken: $SAStoken"
echo "storageAccountName: $storageAccountName"
echo "containerName: $containerName"

# Output all input variables to a log file (append mode with separator)
logFilePath="/home/user/Desktop/ANYRUN_log.txt"  # Adjust path as needed for UNIX
echo "---------------" >> "$logFilePath"
echo "Input parameters at $date" >> "$logFilePath"
echo "filePath: ${filePaths[*]}" >> "$logFilePath"
echo "SAStoken: $SAStoken" >> "$logFilePath"
echo "storageAccountName: $storageAccountName" >> "$logFilePath"
echo "containerName: $containerName" >> "$logFilePath"
echo "---------------" >> "$logFilePath"
echo "Parameters logged to: $logFilePath"

# Define temp folder
tempFolder="/tmp/ANYRUN_Temp"

# Function to check if file is in quarantine and restore it to specified path
restore_from_quarantine() {
    local file="$1"
    local restorePath="$2"
    echo "Checking quarantine for file: $file"
    sudo mdatp threat quarantine restore threat-path --path "$file" --destination-path "$restorePath"
    sleep 5
    restoredFilePath="$restorePath/$(basename "$file")"
    if [ -f "$restoredFilePath" ]; then
        echo "File restored from quarantine successfully to: $restoredFilePath"
        return 0
    else
        echo "File not found in quarantine."
        return 1
    fi
}

# Function to upload file to Blob Storage
upload_to_blob() {
    local file="$1"
    local sas="$2"
    blobName="$(basename "$file")"
    # Ensure SAS starts with '?'
    if [[ ! "$sas" == \?* ]]; then
        sas="?$sas"
    fi
    blobUrl="https://$storageAccountName.blob.core.windows.net/$containerName/$blobName$sas"
    echo "Uploading to URL: $blobUrl"  # Debug: Print URL
    curl -X PUT -T "$file" -H "x-ms-blob-type: BlockBlob" -H "x-ms-version: 2021-04-10" -H "Content-Type: application/octet-stream" "$blobUrl" -v
    if [ $? -eq 0 ]; then
        echo "File uploaded to Blob Storage successfully: $blobName"
        return 0
    else
        echo "Error uploading file"
        return 1
    fi
}

# Main logic
echo "Starting script at $date for files: ${filePaths[*]}"

# Create temp folder if not exists
mkdir -p "$tempFolder"
echo "Temp folder created or exists: $tempFolder"

# Set permissions on temp folder to only current user (owner)
chmod 700 "$tempFolder"
echo "Permissions set on temp folder: accessible only to current user (chmod 700)"

# Add temp folder to MDE exclusions
sudo mdatp exclusion folder add --path "$tempFolder"
echo "Temp folder added to MDE exclusions"

# Track overall success
allSuccess=true

# Process each file path
for path in "${filePaths[@]}"; do
    tempFilePath="$tempFolder/$(basename "$path")"

    # Check if file exists at original path
    if [ -f "$path" ]; then
        # Move to temp folder if exists
        mv -f "$path" "$tempFilePath"
        echo "File moved to temp folder: $tempFilePath"
    else
        # Try to restore from quarantine directly to temp folder
        if restore_from_quarantine "$path" "$tempFolder"; then
            echo "File restored directly to temp folder: $tempFilePath"
        else
            echo "File not found at $path or in quarantine. Skipping this file."
            allSuccess=false
            continue
        fi
    fi

    # Upload to Blob
    if ! upload_to_blob "$tempFilePath" "$SAStoken"; then
        allSuccess=false
    fi

    # Clean up this file
    rm -f "$tempFilePath"
    echo "File removed from temp folder: $tempFilePath"
done

# Final clean up
sudo mdatp exclusion folder remove --path "$tempFolder"
echo "Temp folder removed from MDE exclusions"

# Delete temp folder with error handling
if rm -rf "$tempFolder"; then
    echo "Temp folder deleted successfully; associated permissions removed automatically."
else
    echo "Error deleting temp folder. Permissions may persist if folder remains."
    allSuccess=false
fi

if $allSuccess; then
    echo "Script completed successfully at $date"
else
    echo "Script completed with some failures at $date"
fi