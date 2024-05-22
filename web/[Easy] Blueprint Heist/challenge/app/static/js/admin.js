
function getToken() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('token')
  }

  async function fetchAbsence() {
    const token = getToken();

    const url = `/graphql?token=${token}`;

    const query = `{
        getAllData {
            name
            department
            isPresent
        }
    }`;

    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query }),
    })
    .then(response => response.json())
    .then(data => {
        if (data.errors) {
            console.error("Error fetching data:", data.errors);
        } else {
            const absenceContainer = document.getElementById('absenceContainer');
            absenceContainer.innerHTML = '';

            data.data.getAllData.forEach(({ name, department, isPresent }) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${name}</td>
                    <td>${department}</td>
                    <td>${isPresent ? "Present" : "Absent"}</td>
                `;
                absenceContainer.appendChild(row);
            });
        }
    })
    .catch(error => {
        console.error("Error fetching data:", error);
    });
}

document.getElementById('fetchUserForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const token = getToken()

    const username = document.getElementById('username').value;
    fetch(`/graphql?token=${token}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            query: `{
                getDataByName(name: "${username}") {
                    name
                    department
                    isPresent
                }
            }`
        })
    })
    .then(response => response.json())
    .then(data => {
        const absenceContainer = document.getElementById('absenceContainer');
        absenceContainer.innerHTML = '';
        if (data.errors) {
            console.error('Error fetching user data:', data.errors);
        } else if (data.data.getDataByName) {
            data.data.getDataByName.forEach(({ name, department, isPresent }) => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${name}</td>
                    <td>${department}</td>
                    <td>${isPresent ? "Present" : "Absent"}</td>
                `;
                absenceContainer.appendChild(row);
            });
        } else {
            console.log('No user found with the provided username:', username);
        }
    })
    .catch(error => {
        console.error('Error fetching user data:', error);
    });
});

fetchAbsence()