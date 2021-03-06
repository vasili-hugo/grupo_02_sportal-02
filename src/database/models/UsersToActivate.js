module.exports = (sequelize, dataTypes) => {
    let alias = 'UsersToActivate';
    let cols = {
      id: {
        type: dataTypes.BIGINT(10).UNSIGNED,
        autoNull: false,
        primaryKey: true,
        autoIncrement: true
      },
      email: {
        type: dataTypes.STRING(255),
        autoNull: false,
        unique: true
      },
      password: {
          type: dataTypes.STRING(255),
          allowNull: false
      },
      first_name: {
          type: dataTypes.STRING(255),
          allowNull: false
      },
      last_name: {
          type: dataTypes.STRING(255),
          allowNull: false
      },
      dni: {
        type: dataTypes.BIGINT(10).UNSIGNED,
        allowNull: false,
        unique: true
      },
      cell_phone: {
        type: dataTypes.BIGINT(12),
        allowNull: false
      },
      address: {
        type: dataTypes.STRING(255),
        allowNull: false
      },
      zipcode: {
        type: dataTypes.STRING(8),
        allowNull: false
      },
      city: {
        type: dataTypes.STRING(255),
        allowNull: false
      },
      avatar: {
        type: dataTypes.STRING(255),
        allowNull: false
      },
      is_admin: {
        type: dataTypes.INTEGER,
        allowNull: false
      },
      uuid: {
        type: dataTypes.STRING(255),
        allowNull: false
      },
      created_at: dataTypes.DATE,
      updated_at: dataTypes.DATE
    }
  
    let config = {
      tableName: "users_to_activate",
      timestamps: true,
      createdAt: 'created_at',
      updatedAt: 'updated_at',
      deletedAt: false
    }
  
    const User = sequelize.define(alias, cols, config); 

    return User;
  }