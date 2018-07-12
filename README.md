# AthleteHeadquarters
A new training system for elite athletes, been developing at the University of Melbourne.

For whom following this project, this repositary contains the current back-end(python3) and coach management system(WEB).
This back-end is running on Nectar: </br>see Main page at: https://www.athletehq.online </br> Server's introduction and current apis: https://www.athletehq.online/api

<h2>Prerequisites</h2>

1. Python3: [install python3](https://wiki.python.org/moin/BeginnersGuide/Download "Downloading Python")
2. Git: [install git](https://git-scm.com/downloads "Git Downloads")

<h2>How to run it locally:</h2>

1. Install latest [MongoDB](https://www.mongodb.com/download-center#community "MongoDB Download Center"), use default configuration: 
	```
	localhost: 127.0.0.1
	port number: 27017
	```
2. Clone this repositary:
	```cmd
	$ git clone https://github.com/FrankOfConscious/AthleteHeadquarters.git
	```
3. Install virtualenv: 
	```cmd
	$ pip3 install virtualenv
  	```
	then move into back-end directory, create a virtual environment: 
	```cmd
	$ virtualenv AHQenv
	```
	
4. Activate the virtual environment: 
	```cmd
	$ source AHQenv/bin/activate
	```
	In Windows, use:
	```cmd
	$ cd AHQenv/Scripts
	$ activate
	```
	
5. Install all the dependencies in the virtual environment.

	Install argon2 for flask, used for hashing user's password:
	```cmd
	(AHQenv)$ pip3 install flask-argon2
	```
	Install mongoengine for flask, used for operating mongoDB:
	```cmd
	(AHQenv)$ pip3 install flask_mongoengine
	```
6. Go back to back_end directory, ans set FLASK_APP veriable:
	```cmd
	(AHQenv)$ export FLASK_APP=AHQ.py
	```

	In Windows, use:
	```cmd
	(AHQenv)$ SET FLASK_APP=AHQ.py
	```
7. Run the flask application: 
	```cmd
	(AHQenv)$ flask run
	```
	If succeed, you will see following info in prompt:
	```cmd
	* Running on http://127.0.0.1:5000/  (Press CTRL+C to quit)
	```
	Then you can visit the main page by clicking the url on your local browser, and send http request tool like Postman to test the apis.
8. To terminate the server, press CTRL+C, then you can quit the virtual environment using:
	```cmd
	(AHQenv)$ deactivate
	```

<h2>How to run it on the cloud server:</h2>

1. Refer to [digitalocean's tutorial](https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-uwsgi-and-nginx-on-ubuntu-16-04) to put it on the cloud.
	
	Warning: there is an error at "/etc/nginx/sites-available/myproject" part:
	```
	uwsgi_pass unix:/home/sammy/myproject/myproject.sock;
	```
	should be:
	```
	uwsgi_pass unix:///home/sammy/myproject/myproject.sock;
	```
	Or, you can directly use the configuration files in this repository.
2. The uwsgi and nginx configuration files are in [confi directory](/back_end/config_file/).
3. Remember to change the URLs in html files(located in [back_end/app/templates](/back_end/app/templates/)) to your own URLs(your server's IP address or domain name).

<h2>Update the current server in Nectar:</h2>

Contact Dr Eduardo Velloso and ask for the following things:
1. Private key for authentication to connect with the server. 
2. Username-password pair of the Ubuntu system.
3. Username and password to [GoDaddy.com](https://au.godaddy.com/ "GoDaddy") for the domain name purchased.
4. Username and password to [digitalocean.com](https://www.digitalocean.com/ "DigitalOcean") for the NS service.

<h2>Author<h2>

Yanbo Liao: yliao3@student.unimelb.edu.au

