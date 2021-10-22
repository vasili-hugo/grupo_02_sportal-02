module.exports = (sequelize, dataTypes) => {
  let alias = 'Family';
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
    tableName: "families",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Family = sequelize.define(alias, cols, config); 

  Family.associate = function (models) {
    Family.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'family_id'
    });
  }
  return Family;
}