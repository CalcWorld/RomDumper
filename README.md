# RomDumper
Dumps the ROM and RAM from the official casio calculator emulators

`dump.exe <target(o:rom|a:ram|b:both)> <Emulator PID>`

You can find the emulator PID from the "Details" tab in task manager

The target is either `o`, `a` or `b` specifying ROM, RAM and both respectively

It will attempt to automatically determine the ROM code, but will default to "dump" if it cannot

Pre-built binaries can be downloaded from [here](https://github.com/fxesdev/RomDumper/releases)