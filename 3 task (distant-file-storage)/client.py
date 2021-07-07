from http.client import HTTPConnection
import urllib

headers = {
	'User-agent' : 'thisPython',
	'Accept-Charset' : 'utf-8'
}

print('Введите адрес сервера [IP:port] ')
url = input()
answer = ''
while (answer != '0'):
	print('Выберите действие?\n1 - get file, 2 - rewrite file, 3 - add to file, 4 - delete file, 5 - copy file, 6 - move file, 0 - exit')
	answer = input()
	try:
		connection = HTTPConnection(url)
		response = ''
		if (answer == '1'):
			print('Введите имя файла для получения')
			filename = input()
			print('Введите путь для сохранения файла')
			path = input()
			connection.request('GET', '/' + filename, headers=headers)
			response = connection.getresponse()
			content = response.read()
			print('HTTP/1.0' if response.version == 10 else 'HTTP/1.1', response.status, 'this file or path are not exist')
			if (response.status == 200):
				f = open(path + "\\" + filename, "wb")
				f.write(content)
				f.close()
		if (answer == '2'):
			print('Введите имя файла для перезаписи')
			filename = input()
			print('Enter content')
			body = {'content' : input()}
			connection.request('PUT', '/' + filename, headers=headers, body=urllib.parse.urlencode(body))
		if (answer == '3'):
			print('Введите имя файла для дозаписи')
			filename = input()
			print('Введите текст:')
			body = {'content' : input()}
			connection.request('POST', '/' + filename, headers=headers, body=urllib.parse.urlencode(body))
		if (answer == '4'):
			print('Введите имя файла для удаления')
			connection.request('DELETE', '/' + input(), headers=headers)
		if (answer == '5'):
			print('Введите путь к файлу для копирования')
			filename = input()
			print('Новый путь')
			path = input()
			print('Новое имя файла')
			newFilename = input()
			body = {'newPath' : path, 'newFilename' : newFilename}
			connection.request('COPY', '/' + filename, headers=headers, body=urllib.parse.urlencode(body))
		if (answer == '6'):
			print('Введите имя файла для перемещения')
			filename = input()
			print('Введите новый путь')
			body = {'newPath' : input()}
			connection.request('MOVE', '/' + filename, headers=headers, body=urllib.parse.urlencode(body))
		if (answer in {'2', '3', '4', '5', '6'}):
			response = connection.getresponse()
			print('HTTP/1.0' if response.version == 10 else 'HTTP/1.1', response.status, response.reason)
			print(response.getheader('message'))
			response.read()
		connection.close()
	except ConnectionRefusedError:
		print('Ошибка соединения')
		answer = '0'