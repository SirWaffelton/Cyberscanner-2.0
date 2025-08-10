from flask import Flask
app = Flask(__name__)

@app.route("/")
def home():
    return "This is a vulnerable HTTPS server test."

if __name__ == "__main__":
    app.run(ssl_context='adhoc', port=443)
