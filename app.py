from flask import Flask

app = Flask(__name__)

# Route for the homepage
@app.route('/')
def hello():
    return 'Say Hi!'

if __name__ == '__main__':
    app.run(debug=True)