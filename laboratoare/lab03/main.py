from flask import Flask, json, request

app = Flask(__name__)
movies = []
i = 1


@app.get('/movies')
def getMovies():
    return (json.dumps(movies), 200)


@app.post('/movies')
def postMovie():
    global movies
    global i

    newMovie = request.json
    if newMovie and 'nume' in newMovie and newMovie['nume'] != '':
        movies.append({'id': i, 'nume': newMovie['nume']})
        i += 1
        return ('', 201)
    else:
        return ('', 400)


@app.put('/movie/<int:id>')
def updateMovieNameById(id):
    global movies
    movie = request.json
    for j in range(len(movies)):
        if movies[j]['id'] == id:
            if 'nume' not in movie:
                return ('', 400)
            movies[j]['nume'] = movie['nume']
            return ('', 200)
    return ('', 404)


@app.get('/movie/<int:id>')
def getMovieById(id):
    global movies
    for movie in movies:
        if movie['id'] == id:
            return (json.dumps(movie), 200)
    return ('', 404)


@app.delete("/movie/<int:id>")
def deleteMovieById(id):
    global movies
    for j in range(len(movies)):
        if movies[j]['id'] == id:
            movies.pop(j)
            return ('', 200)
    return ('', 404)


@app.delete("/reset")
def deleteMovies():
    global movies
    global i
    i = 1
    movies = []
    return ('', 200)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
