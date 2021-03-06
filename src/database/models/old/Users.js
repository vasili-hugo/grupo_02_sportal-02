module.exports = function (sequelize, dataTypes) {
    let alias = 'Users';

    let cols = {
        id: {
            type: dataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        email: {
            type: dataTypes.STRING
        },
        password: {
            type: dataTypes.STRING
        },
        first_name: {
            type: dataTypes.STRING
        },
        last_name: {
            type: dataTypes.STRING
        },
        dni: {
            type: dataTypes.INTEGER
        },
        cell_phone: {
            type: dataTypes.INTEGER
        },
        address: {
            type: dataTypes.STRING
        },
        zipcode: {
            type: dataTypes.STRING
        },
        city: {
            type: dataTypes.STRING
        },
        avatar: {
            type: dataTypes.STRING
        },
        is_admin: {
            type: dataTypes.INTEGER
        }
    }

    let config = {
        tableName: 'users',
        timestamps: false
    }

    let Users = sequelize.define(alias, cols, config);

    return Users;
}