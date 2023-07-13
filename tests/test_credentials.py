import pytest
import requests

user = {
    'username': 'test_user',
    'password': 'test_password12',
    'new_password': 'new_password12'
}

def test_register_user():
    url = 'http://localhost:5000/register'
    data = {
        'username': user['username'],
        'password': user['password']
    }
    response = requests.post(url, json=data)
    assert response.status_code == 200
    assert response.json()['message'] == 'User registered successfully.'

def test_register_user_already_exists():
    url = 'http://localhost:5000/register'
    data = {
        'username': user['username'],
        'password': user['password']
    }
    response = requests.post(url, json=data)
    assert response.status_code == 400
    assert response.json()['error'] == 'Username already exists.'

def test_register_user_invalid_password():
    url = 'http://localhost:5000/register'
    data = {
        'username': user['username'],
        'password': 'invalid_password'
    }
    response = requests.post(url, json=data)
    assert response.status_code == 400
    assert response.json()['error'] == 'Password must contain 5 letters and 2 numbers. False'

def test_fail_login_user():
    url = 'http://localhost:5000/login'
    data = {
        'username': user['username'],
        'password': 'wrong_password'
    }
    response = requests.post(url, json=data)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid username or password.'

def test_login_user():
    url = 'http://localhost:5000/login'
    data = {
        'username': user['username'],
        'password': user['password']
    }
    response = requests.post(url, json=data)
    assert response.status_code == 200
    assert response.json()['message'] == 'User logged in successfully.'

def test_change_password():
    url = 'http://localhost:5000/change_password'
    data = {
        'username': user['username'],
        'old_password': user['password'],
        'new_password': user['new_password']
    }
    response = requests.post(url, json=data)
    assert response.status_code == 200
    assert response.json()['message'] == 'Password changed successfully.'

    login_url = 'http://localhost:5000/login'
    login_data = {
        'username': user['username'],
        'password': user['new_password']
    }
    login_response = requests.post(login_url, json=login_data)
    assert login_response.status_code == 200
    assert login_response.json()['message'] == 'User logged in successfully.'
