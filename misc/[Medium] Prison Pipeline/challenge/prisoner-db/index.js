const fs = require('fs');
const yaml = require('js-yaml');
const CurlWrapper = require('./curl');

const curl = new CurlWrapper();

/**
 * Database interface for prisoners of Prison-Pipeline.
 * @class Database
 * @param {string} repository - Path to existing database repository.
 * @example
 * const db = new Database('/path/to/repository');
**/

class Database {
    constructor(repository) {
        this.repository = repository;
        this.metadata = this.readJSON(repository + '/index.json');
    }

    listPrisonersIds() {
        return this.metadata.prisoner_ids;
    }

    getPrisoners() {
        let prisoners = [];
        for (let id of this.metadata.prisoner_ids) {
            let prisoner = this.getPrisoner(id);
            if (prisoner.id) prisoners.push({id: prisoner.id, raw: prisoner.raw, ...prisoner.data});
        }
        return prisoners;
    }

    getPrisoner(id) {
        let prisoner = {id: null, raw: '', data: {}};
        try {
            if (this.metadata.prisoner_ids.includes(id)) {
                prisoner = {
                    id: id,
                    raw: this.readYAML(this.repository + '/' + id + '.yaml')
                };
                try {
                    let details = yaml.load(prisoner.raw).prisoner_profile;
                    prisoner.data = details;
                }
                catch (e) {
                    prisoner.data = {};
                }
                return prisoner;
            }

            return {};
        }
        catch (e) {
            return {};
        }
    }

    addPrisoner(prisoner) {
        this.metadata.prisoner_ids.push(prisoner.id);
        this.writeJSON(this.repository + '/index.json', this.metadata);

        this.writeYAML(this.repository + '/' + prisoner.id + '.yaml', prisoner.data);

        return true;
    }

    updatePrisoner(prisoner) {
        if (this.metadata.prisoner_ids.includes(prisoner.id)) {
            this.writeYAML(this.repository + '/' + prisoner.id + '.yaml', prisoner.data);
            return true;
        }
        return false;
    }

    async importPrisoner(url) {
        try {
            const getResponse = await curl.get(url);
            const xmlData = getResponse.body;

            const id = `PIP-${Math.floor(100000 + Math.random() * 900000)}`;

            const prisoner = {
                id: id,
                data: xmlData
            };

            this.addPrisoner(prisoner);
            return id;
        }
        catch (error) {
            console.error('Error importing prisoner:', error);
            return false;
        }
    }


    readJSON(path) {
        try {
            return JSON.parse(fs.readFileSync(path, 'utf8'));
        }
        catch (e) {
            return {};
        }
    }

    writeJSON(path, data) {
        try {
            fs.writeFileSync(path, JSON.stringify(data, null, 2));
        }
        catch (e) {
            return false;
        }
    }

    readYAML(path) {
        try {
            return fs.readFileSync(path, 'utf-8');
        }
        catch (e) {
            return '';
        }
    }

    writeYAML(path, data) {
        try {
            fs.writeFileSync(path, data);
        }
        catch (e) {
            return false;
        }
    }
}

module.exports = Database;