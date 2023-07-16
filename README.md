# Mega Folder Sync

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)

## About <a name = "about"></a>

I, like many people, am extremely lazy and struggle to make sure that I continually check and download shows that are currently running when I'm not activley watching them. Sure I'll get around to it, but I'd like to make sure my shows are ready to go when I want to watch them.

This python script is a way to interface with MEGA's extremely convoluted API and download items from folders defined within the JSON file.

This isn't an elaborate script or anything, but it will pass over items that already exist in folders that match **exact** names, avoiding any unnecessary downloads (at some point I'd like to be more generic and only check on keywords).

## Getting Started <a name = "getting_started"></a>

### Prerequisites

Python 3.9 or earlier is **required**. The MEGA python module has been abandoned for several years now and was never updated to support more modern python versions. I tested this on 3.9 and 3.11, where 3.11 does not work with the MEGA module.

### Installing

Before running the script, make sure you run

```pip install -r requirements.txt```

or

```python -m pip install -r requirements.txt```

to get all the necessary modules to execute.

## Usage <a name = "usage"></a>

First, ensure you have all items you want to track located in the *file_locations.json* file provided in the repository. There is a template to start with, and can support multiple items. The script does to a courtesy check that the URL is valid and will create a directory if the local provided directory does not exist.

Once the contents of *file_locations.json* has been updated, call ```python mega_folder_sync.py```. This will print out to the console the folders and items within the folder it is looking for, skipping, and downloading.
