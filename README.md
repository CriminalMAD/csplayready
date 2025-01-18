# csplayready
C# implementation of Microsoft's Playready DRM CDM (Content Decryption Module)


## Installation
```shell
dotnet add package csplayready
```

Run `csplayready --help` to view available cli functions


## Devices
Run the command below to create a Playready Device (.prd) from a `bgroupcert.dat` and `zgpriv.dat`:
```shell
csplayready create-device -c bgroupcert.dat -k zgpriv.dat
```

Test a playready device:
```shell
csplayready test DEVICE.prd
```

> [!IMPORTANT]  
> There currently isn't a proper method of extracting Group Certificates/Keys. They can be found inside older Samsung phones/Smart TVs, Windows DLLs and set-top-boxes in encrypted form.

Export a provisioned device to its raw .dat files
```shell
csplayready export-device DEVICE.prd
```

## Usage
An example code snippet:

```csharp
...
```

## Disclaimer

1. This project requires a valid Microsoft Certificate and Group Key, which are not provided by this project.
2. Public test provisions are available and provided by Microsoft to use for testing projects such as this one.
3. This project does not condone piracy or any action against the terms of the DRM systems.
4. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial & Error.
5. Do not use this program to decrypt or access any content for which you do not have the legal rights or explicit permission.
6. Unauthorized decryption or distribution of copyrighted materials is a violation of applicable laws and intellectual property rights.
7. This tool must not be used for any illegal activities, including but not limited to piracy, circumventing digital rights management (DRM), or unauthorized access to protected content.
8. The developers, contributors, and maintainers of this program are not responsible for any misuse or illegal activities performed using this software.
9. By using this program, you agree to comply with all applicable laws and regulations governing digital rights and copyright protections.

## Credits
+ [mspr_toolkit](https://security-explorations.com/materials/mspr_toolkit.zip)
