module.exports = (sequelize, dataTypes) => {
  let alias = 'Sex';
  let cols = {
    id: {
      type: dataTypes.BIGINT(10).UNSIGNED,
      allowNull: false,
      primaryKey: true,
      autoIncrement: true
    },
    desc: {
      type: dataTypes.STRING(255),
      allowNull: false
    },
    created_at: dataTypes.DATE,
    updated_at: dataTypes.DATE
  }

  let config = {
    tableName: "sex",
    timestamps: true,
    createdAt: 'created_at',
    updatedAt: 'updated_at',
    deletedAt: false
  }

  const Sex = sequelize.define(alias, cols, config); 

  Sex.associate = function (models) {
    Sex.hasMany(models.Product, {
      as: "Product",
      foreignKey: 'sex_id'
    });
  }
  return Sex;
}
