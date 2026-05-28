#!/bin/bash


[[ -n "$1" && -n "$2" ]] || { echo "Usage: $(basename "$0") <input dir> <destination dir>"; exit 0; }

declare -r input_dir="$1"
declare -r destination_dir="$2"

declare -r key_id="" # Set the GPG recipient key ID here!
declare -r date_format="+%Y%m%d%H%M%S"


exit_on_error() {
    echo "An error occurred: $1" >&2
    exit 1
}

set_permissions() {
    echo "Adjusting permissions for $1..."
    chmod o-rwx "$1" || exit_on_error "Failed to set permissions for $1"
}

remove_or_fail() {
    echo "Removing $1"
    rm -rf "$1" || exit_on_error "Could not delete $1"
}


[[ -d "$destination_dir" ]] || exit_on_error "Destination ${destination_dir} doesn't exist!"
[[ -d "$input_dir" ]] || exist_on_error "Destination ${destination_dir} doesn't exist!"

[[ -x $(which gpg) ]] || exit_on_error "gpg is not installed on your system!"
[[ -x $(which tar) ]] || exit_on_error "tar is not installed on your system!"

temp_destination_dir="$(readlink -m "$destination_dir/temp")"
[[ -d "$temp_destination_dir" ]] || mkdir -p "$temp_destination_dir" || exit_on_error "Could not create temp directory $temp_destination_dir"

input_dir_tar=$(readlink -m "$temp_destination_dir/$(basename "$input_dir")_$(date $date_format).tar.gz")
[[ ! -e "$input_dir_tar" ]] || exit_on_error "$input_dir_tar already exists. Please rename or delete it!"

echo "Compressing folder $input_dir to $input_dir_tar..."
tar -czf "$input_dir_tar" "$input_dir" || exit_on_error "Could not create tar $input_dir_tar"
echo "Created $input_dir_tar"

set_permissions "$input_dir_tar"

encrypted_input_tar=$(readlink -m "$input_dir_tar.enc")
[[ ! -e "$encrypted_input_tar" ]] || exit_on_error "$encrypted_input_tar already exists. Please rename or delete it!"

echo "Encrypting $input_dir_tar to $encrypted_input_tar..."
gpg --encrypt \
    --recipient "$key_id" \
    --output "$encrypted_input_tar" \
    "$input_dir_tar" || exit_on_error "An error occurred while encrypting $input_dir_tar!"

echo "Created $encrypted_input_tar"

set_permissions "$encrypted_input_tar"
remove_or_fail "$input_dir_tar"

echo "Moving backup to $destination_dir"
mv "$encrypted_input_tar" "$destination_dir" || exit_on_error "Could not move $encrypted_input_tar to $destination_dir"

echo "Removing temp directory at destination $temp_destination_dir"
remove_or_fail "$temp_destination_dir"

echo "Done!"