import requests

# ex 1
# post request to https://sprc.dfilip.xyz/lab1/task1 with url encoded data name, group and post params secret and header secret
res = requests.post('https://sprc.dfilip.xyz/lab1/task1/check?nume=Filip&grupa=SPRC&secret=SPRC',
                    data={'secret': 'SPRCisNice'}, headers={'secret2': 'SPRCisBest'})

# print response
print(res.text)
# {"status":"ok","proof":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3aG8iOnsibnVtZSI6WyJGaWxpcCJdLCJncnVwYSI6WyJTUFJDIl19LCJkaWQiOiJ0YXNrMSJ9.YfGv8o0v3KkPpd6TSGsRGKmAxi0U53xpROE_jJRdKLc"}


# ex 2
# post request to sprc.dfilip.xyz/lab1/task2 with json {’username’:’sprc’, ’password’:’admin’, ’nume’:’numele vostru’}
res = requests.post('https://sprc.dfilip.xyz/lab1/task2',
                    json={'username': 'sprc', 'password': 'admin', 'nume': 'Radu'})

#print response
print(res.text)
# {"status":"ok","proof":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3aG8iOnsibnVtZSI6IlJhZHUifSwiZGlkIjoidGFzazIifQ.N5RRged23_4StU5HL_KJ-YH7pOsH4Zzzax4r-xtk7ZQ"}

#ex 3
s = requests.Session()
res = s.post('https://sprc.dfilip.xyz/lab1/task3/login',
                    json={'username': 'sprc', 'password': 'admin', 'nume': 'Radu'})

# get the cookie session
# get request /lab1/task3/check
res = s.get('https://sprc.dfilip.xyz/lab1/task3/check')

# print response
print(res.text)

# {"status":"ok","proof":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3aG8iOnsibnVtZSI6IlJhZHUifSwiZGlkIjoidGFzazMifQ.Yw9WLvqjGAoCuRnT3kbiDFtl4CHi4O74znVGe-DHq00"}



