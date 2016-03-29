# SearchGiant
### Command line forensic imaging utility for cloud services.

This program was designed for my Applied Research Project at John Jay University for my masters degree in digital forensics and cyber security. It's a pretty simple but powerful command line utility that does it's best to create forensically sound acquisition of remote cloud data on some popular providers:

* Google Drive
* GMail
* Dropbox

I do plan on adding more providers when I get more time to work on it.

#### Installation
Since I wrote this with the intention of not relying on any third party dependencies in order to be as portable as possible, there is no installation required.

Simply run 

```bash
python3 searchgiant.py
```

#### Basic Usage
```
usage: searchgiant.py [-h] [--mode mode] [--threads threads] [--prompt]
                      project_dir service_type

Cloud Service forensic imaging tool

positional arguments:
  project_dir           Path where project will be created. If project already
                        exists it will use existing settings
  service_type          Accepted values: google_drive, dropbox, gmail

optional arguments:
  -h, --help            show this help message and exit
  --mode mode, -m mode  Synchronization mode. Accepted values are: full,
                        metadata. Default value is: full
  --threads threads, -t threads
                        Amount of parallel threads used to download files
  --prompt, -p          Prompt before actually downloading anything

```

#### Screenshots
![Main](http://imgur.com/GE8lQR6.png)

![Gmail](http://imgur.com/YH8c35F.png)

![GDrive](http://imgur.com/AywmmgZ.png)
