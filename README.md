# tabstate-parser

The TabState Parser is a Python script designed to parse the content of "bin" files generated by the native Notepad auto-save feature in Windows 11. This feature allows users to recover their notes even after a crash or system reboot. The files are stored in `%LOCALAPPDATA%\Packages\Microsoft.WindowsNotepad_8wekyb3d8bbwe\LocalState`. 

> [!note]
> The structure names are not documented by microsoft. So i just put a custom name according to my liking. No hate pls

## Sample Usage
- Auto parse unsaved and saved state file
```python
tsp = TabStateParser(
	file_path="path/to/file.bin",
	raw=True
)
file_struct = tsp.parse()
```

- You can actually overwrite parse...() function with other file stream
```python
tsp = TabStateParser(
	file_path="path/to/file.bin",
	raw=True
)
new_stream = open("/path/to/new/file.bin", "rb")
file_struct = tsp.parse_saved(
				file_stream=new_stream
			  )
```

## Credits
- https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/
- https://u0041.co/posts/articals/exploring-windows-artifacts-notepad-files/