from flask import Flask

app = Flask(__name__)


@app.get('/')
def getMovies():
    return ('Hello docker', 200)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
