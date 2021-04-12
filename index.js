// Custom written stream parser for parsing iptables log entries
class LogStreamParser {

	constructor(input) { 
		this.Init(input);
	}

	// Initalize with the given input string.
	// This allows the parser to be re-used once it's initalized for the first time
	Init(input) {
		this._in = input;
		this._curr = this._in;
	}

	// Peek and eat the next char in the sequence.
	GetChar() {
		var chr=this.PeekChar();
		this._curr = this._curr.slice(1);
		return chr;
	}

	// Peek the next char in the sequence without eating it from the sequence.
	PeekChar() {
		var chr=this._curr.slice(0, 1);
		return chr;
	}

	// Eat a character without caring about it.
	EatChar() {
		this.GetChar();
	}

	// Check if the string is empty.
	Empty() {
		return this._curr === "";
	}

	// Returns true if <chr> is a space
	IsSpace(chr) {
		return chr === ' ';
	}

	// Returns true if <chr> is the '=' character.
	IsEqualsToken(chr) {
		return chr === '=';
	}

	// Read an identifier, stopping at either a space or a token.
	// Any tokens after are not eaten by this function and should be eaten by a higher level parse routine
	ReadIdentifier() {
		var identifier = "";

		if(this.Empty())
			return "";

		var chr = this.GetChar();

		while(!this.IsSpace(chr) || !this.IsEqualsToken(chr)) {
			identifier += chr;

			// break if we're about to hit a token or space, but don't eat it
			if(this.IsEqualsToken(this.PeekChar()) || this.IsSpace(this.PeekChar()))
				break;

			if(this.Empty())
				break;

			chr = this.GetChar();
		}

		return identifier;
	}

	// Parse an entry. Returns an JS object with the key and value,
	// where the value is null if there was no value parsable.
	ParseEntry() {
		var key = this.ReadIdentifier();

		// Peek if the next character is the = token.
		if(this.IsEqualsToken(this.PeekChar())) {
			// Eat the equals token
			this.EatChar();

			// No value, even if there was a = token.
			// This is a valid possibility and testcases prove it
			if(this.IsSpace(this.PeekChar())) {
				this.EatChar();
				return { key: key, value: null };
			}

			// Read the value and eat the space that ReadIdentifier() stopped on
			var value = this.ReadIdentifier();
			this.EatChar();

			return { key: key, value: value };
		} else {
			// This is "SYN" or "DF" or something
			this.EatChar();
			return { key: key, value: null };
		}
	}

};

/**
 * Local instance of the log stream parser so we don't keep creating useless objects
 *
 * @type LogStreamParser
 */
var parser = null;

module.exports = class IPTablesLogParser {
	constructor() {

	}

	// Parse iptables log entry into a JSON object.
	ParseIPTablesLog(entry) {
		var obj = {
			details: {},
			values: {}
		};

		// Ignore invalid log entries.
		if(entry.indexOf("IN=") === -1) {
			obj.details.invalid = true;
			return obj;
		}

		var slicedup = null;

		// This is a little questionable, but it works.	
		obj.details.time = entry.slice(1, entry.indexOf(']'));
		slicedup = entry.slice(entry.indexOf(']')+2);

		// Get the log prefix in a kind of hacky manner.
		obj.details.prefix = slicedup.slice(0,slicedup.indexOf("IN="));
		slicedup = slicedup.slice(slicedup.indexOf("IN="));

		// Create the parser if it needs to be created,
		// otherwise initalize the existing parser.
		if(parser === null)
			parser = new LogStreamParser(slicedup);
		else
			parser.Init(slicedup);
		
		// Keep parsing entries until the stream is emptied.
		while(!parser.Empty()) {
			var entry = parser.ParseEntry();
			obj.values[entry.key] = entry.value;
		}

		return obj;
	}
};
