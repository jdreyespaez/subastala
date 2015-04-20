// grab the packages that we need for the user model
var mongoose     = require('mongoose');
var Schema       = mongoose.Schema;
var bcrypt 		 = require('bcrypt-nodejs');

// user schema 
var UserSchema   = new Schema({
	name: String,
	//JD COMM: Al definir el índice como único, le estamos diciendo a Mongoose que sólo pueda seguir un path único, esto quiere decir que username no se repetirá.
	username: { type: String, required: true, index: { unique: true }},
	//JD COMM: Otra funcionalidad que usaremos de mongoose es implementar select: false como uno de los atributos del password. Cuando se hace un petición de los usuarios no se devolverá la clave cuando sea llamada explícitamente. 
	password: { type: String, required: true, select: false }
});

// hash the password before the user is saved
//== JD COMM: 2º.	Nos encargaremos que nunca se guarden las claves como un simple texto en la base de datos. 
UserSchema.pre('save', function(next) {
	var user = this;

	// hash the password only if the password has been changed or user is new
	if (!user.isModified('password')) return next();

	// generate the hash
	bcrypt.hash(user.password, null, null, function(err, hash) {
		if (err) return next(err);

		// change the password to the hashed version
		user.password = hash;
		next();
	});
});

// method to compare a given password with the database hash
UserSchema.methods.comparePassword = function(password) {
	var user = this;

	return bcrypt.compareSync(password, user.password);
};

module.exports = mongoose.model('User', UserSchema);