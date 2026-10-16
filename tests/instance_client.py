"""Test helper for the public asynchronous API; capabilities never enter logs."""
import secrets
import time


def upload(client, data):
    headers = {'Authorization': 'Bearer ' + secrets.token_hex(32)}
    response = client.post('/api/instances', content=data, headers=headers)
    assert response.status_code == 201, response.text
    return '/api/instances/' + response.json()['id'], headers


def query(client, handle, operation='packets', payload=None):
    base, headers = handle
    response = client.post(base + '/jobs', headers=headers,
                          json={'operation': operation, 'payload': payload or {}})
    assert response.status_code == 202, response.text
    job_url = base + '/jobs/' + response.json()['id']
    deadline = time.monotonic() + 35
    while time.monotonic() < deadline:
        response = client.get(job_url, headers=headers)
        assert response.status_code == 200, response.text
        state = response.json()
        if state['state'] in {'done', 'error'}:
            client.delete(job_url, headers=headers)
            return state
        time.sleep(.02)
    raise AssertionError('Analysis did not complete')
