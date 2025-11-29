curr_dir=$(dirname "$0")
parent_dir=$(dirname "$curr_dir")
db_folder="$parent_dir/db_folder"
mkdir -p $db_folder
projects_folder="$parent_dir/projects"
mkdir -p $projects_folder