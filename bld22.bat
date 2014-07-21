cl /nologo /MD /W3 /Od /D WIN32 /D _WINDOWS  -I"C:\Apache22\include"  /c /Zi /Fdmod_wbt.pdb /Fomod_wbt.lo mod_wbt.c
link kernel32.lib /nologo /debug /subsystem:windows /dll /machine:I386 /libpath:"c:\Apache22\lib" /PDB:mod_wbt.pdb /out:mod_wbt.so mod_wbt.lo libhttpd.lib dbghelp.lib
copy mod_wbt.so c:\apache22\modules
copy mod_wbt.pdb c:\apache22\modules
