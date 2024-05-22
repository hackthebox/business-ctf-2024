window.onload = () => {
    // Tight, tight, tight! Oh... blue, yellow, pink!
    // Whatever, man, just keep bringing me that!
    window.colors = ['blue', 'yellow', 'pink', 'red', 'purple'];
    window.color_index = 0;
    window.load_first = true;

    loadAllPrisoners();
}

const loadAllPrisoners = async () => {
    await fetch('/api/prisoners', {
        method: 'GET'
    })
    .then(async (response) => {
        if (response.status == 200) {
            prisoners = await response.json();
            $('.prisoner-list').html('');
            prisoners.forEach(prisoner => {
                populatePrisonerCard(prisoner);
            });
        }
        else {
            $('#update-resp').text('Failed to load prisoner data!');
            $('#update-resp').show();
        }
    })
    .catch((error) => {
        console.log(error);
    });
}


const populatePrisonerCard = (prisoner) => {
    let cardColor = window.colors[window.color_index];
    window.color_index = (window.color_index + 1) % window.colors.length;

    if (window.load_first) {
        window.load_first = false;
        loadPrisonerFile(prisoner.id);
    }

    template = `
    <div class="flex column mb-1 hoverable ${cardColor}">
        <div class="flex column module right reveal mt-2">
            <button class="green fill" onclick="loadPrisonerFile('${prisoner.id}')">
            LOAD
            </button>
        </div>
        <div class="flex justify-space-between w-100 glow text">
            <strong>
            ${prisoner.name}
            </strong>
            <strong>
            ${prisoner.id}
            </strong>
        </div>
        <div class="glow flex row justify-space-between p-1 pb-2 flex-wrap">
            <div class="flex column px-1">
                <strong>age</strong>
                <span class="glow text">${prisoner.age}</span>
            </div>
            <div class="flex column px-1">
                <strong>height</strong>
                <span class="glow text">${prisoner.height}</span>
            </div>
            <div class="flex column px-1">
                <strong>zone</strong>
                <span class="glow text">${prisoner.prisoner_zone}</span>
            </div>
            <div class="flex column px-1">
                <strong>cell</strong>
                <span class="glow text">${prisoner.prisoner_cell}</span>
            </div>
        </div>
    </div>
    `;

    $('.prisoner-list').append(template);
}

const loadPrisonerFile = async (id) => {

    $('#profile-editor').val('');
    $('#update-resp').hide();

    await fetch(`/api/prisoners/${id}`, {
        method: 'GET'
    })
    .then(async (response) => {
        if (response.status == 200) {
            prisonerRecord = await response.json();
            $('#profile-editor').val(prisonerRecord.raw);
            $('#profile-id').val(prisonerRecord.id);
        }
        else {
            $('#update-resp').text('Failed to load prisoner data!');
            $('#update-resp').show();
        }
    })
    .catch((error) => {
        $('#update-resp').text('Something went wrong!');
        $('#update-resp').show();
    });
}

const importProfile = async () => {

    let url = $('#prisoner-url').val();

    await fetch('/api/prisoners/import', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({url}),
    })
    .then(res => res.json()
    .then(response => {
        $('#import-resp').val(response.message);
        $('#import-resp').show()
    
        if (res.status == 200) {;
            location.reload();
        }
    })
    )
    .catch((error) => {
        $('#import-resp').val('Something went wrong!');
        $('#import-resp').show();
    });
}