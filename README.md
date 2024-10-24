## API Setup

-   Go to http://my.telegram.org and log in.
-   Click on API development tools and fill the required fields.
-   put app name you want & select other in platform Example :
-   copy "api_id" & "api_hash" after clicking create app ( will be used in setup.py )

## How To Install and Use

`$ pkg install -y git python`

`$ git clone https://github.com/Antiokh/tgs.py`

`$ cd tgs.py`

-   Install requierments

`$ python3 setup.py -i`

-   setup configration file ( apiID, apiHASH )

`$ python3 setup.py -c`

-   To Genrate User Data

`$ python3 tgs.py scrape`

-   To Add Users

`$ python3 tgs.py add`

-   To Spam

`$ python3 tgs.py spam -i members.csv`

## To make it work on Termux:

1.  Install Termux from F-Droid (as Google Play’s version can’t use all the mirrors for packeges)
2.  Run `$ pkg update & pkg upgrade -y`
3.  Run `$ pkg install rust`
4.  Run `$ pkg install termux-api`
5.  Run `$ pkg-install python-pip`
