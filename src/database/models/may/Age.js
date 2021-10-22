module.exports = (sequelize, dataTypes) => {
  let alias = 'Age';
  let cols = {
    id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      autoNull: false,
      primaryKey: true,
      autoIncrement: true
    },
    desc: {
      type: dataTypes.STRING(255),
      autoNull: false
    },
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "ages",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Age = sequelize.define(alias, cols, config); 

  Age.associate = function (models) {
    Age.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'age_id'
    });
  }
  return Age;
}