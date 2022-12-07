///
// validation
///

// Validation function factory
function validate(cond, msg) {
	return function(e) {
		const errSpan = e.target.parentNode.querySelector('.validation');
		if (!cond(e.target.value)) {
			errSpan.textContent = msg;
		} else if (errSpan.textContent === msg) {
			errSpan.textContent = '';
		}
	}
}

// Valid hex value
const validHex = validate(str => /^[0-9a-fA-F\s]*$/.test(str),
	'Value is not a valid hexadecimal value.');
document.querySelector('#ip_id').addEventListener('change', validHex);
document.querySelector('#ip_ttl').addEventListener('change', validHex);
document.querySelector('#icmp_id').addEventListener('change', validHex);
document.querySelector('#icmp_seq').addEventListener('change', validHex);

// Maximum Length
const maxlen = n => validate(str => str.replaceAll(' ', '').length <= n,
	'Value is too long.');
document.querySelector('#ip_id').addEventListener('change', maxlen(4));
document.querySelector('#ip_ttl').addEventListener('change', maxlen(2));
document.querySelector('#icmp_id').addEventListener('change', maxlen(4));
document.querySelector('#icmp_seq').addEventListener('change', maxlen(4));

document.querySelector('#icmp_data').addEventListener('change',
	validate(str => str.length <= 65507, 'Value is too long.'));

// Valid IPv4 address in dot notation
const validIP = validate(str => {
	if (str === '') return true;
	const nums = str.split('.');
	if (nums.length !== 4) return false;
	for (let n of nums) {
		n = parseInt(n);
		if (Number.isNaN(n) || n < 0 || n > 255) return false;
	}
	return true;
}, 'Value is not a valid IP address.');
document.querySelector('#ip_src').addEventListener('change', validIP);
document.querySelector('#ip_dst').addEventListener('change', validIP);

///
// Calculate & Show Output
///

// Returns a the Number `n` as a string of its hexadecimal value with at most
// `d` leading zeroes. Spaces are added for readability.
const asHex = (n, d) => n.toString(16).padStart(d, '0').replace(/(..)/g, '$1 ')
	.slice(0, -1);

// Parse an IPv4 address in dot notation into an array of two 16-bit words.
function parseIP(ip) {
	const nums = ip.split('.');
	return [(nums[0] << 8) | nums[1],
		(nums[2] << 8) | nums[3]];
}

// Calculate a checksum given an array of 16 bit words
function checksum(data) {
	let sum = 0;
	for (const word of data) {
		let ones = sum + word;
		if (ones >= (1 << 16)) ones = (ones + 1) % (1 << 16);
		sum = ones;
	}
	return 0xffff - sum;
}

function go() {
	// don't run if anything is invalid
	const validations = document.querySelectorAll('.validation');
	if ([...validations].some(el => el.textContent !== '')) {
		document.querySelector('#output_bin').textContent = "Error";
		return;
	}
	// 

	// get the header fields and parse them
	const ip_id = parseInt(document.querySelector('#ip_id').value, 16) || 0;
	const ip_ttl = parseInt(document.querySelector('#ip_ttl').value, 16) || 0;
	const ip_src = parseIP(document.querySelector('#ip_src').value || '127.0.0.1');
	const ip_dst = parseIP(document.querySelector('#ip_dst').value || '127.0.0.1');
	const icmp_id = parseInt(document.querySelector('#icmp_id').value, 16) || 0;
	const icmp_seq = parseInt(document.querySelector('#icmp_seq').value, 16) || 0;
	let icmp_data = document.querySelector('#icmp_data').value;

	// align data to 16 bits
	icmp_data = icmp_data.length % 2 === 0 ? icmp_data : icmp_data + '\0';

	// calculate the IP packet length
	const ip_len = icmp_data.length + 28;
	document.querySelector('#ip_len').textContent = asHex(ip_len, 4);


	// calculate the IP header checksum
	const ip_chkdata = [(4 << 12) | (5 << 8) | 0, ip_len, ip_id, 0,
		(ip_ttl << 8) | 1, 0, ...ip_src, ...ip_dst];
	if (Number.isNaN(ip_chkdata)) return alert('Error');
	const ip_chk = checksum(ip_chkdata);
	document.querySelector('#ip_chk').textContent = asHex(ip_chk, 4);

	// calculate the ICMP header checksum
	let icmp_chkdata = [(8 << 8) | 0, 0, icmp_id, icmp_seq];
	for (let i = 0; i < icmp_data.length; i += 2) {
		icmp_chkdata.push((icmp_data.charCodeAt(i) << 8) |
			icmp_data.charCodeAt(i + 1));
	}
	if (Number.isNaN(icmp_chkdata)) return alert('Error');
	const icmp_chk = checksum(icmp_chkdata);
	document.querySelector('#icmp_chk').textContent = asHex(icmp_chk, 4);

	// output everything to the output bin
	ip_chkdata[5] = ip_chk;
	icmp_chkdata[1] = icmp_chk;
	document.querySelector('#output_bin').textContent = ip_chkdata.map(n =>
		asHex(n, 4)).join(' ') + ' ' + icmp_chkdata.map(n =>
			asHex(n, 4)).join(' ');
}

const inputs = document.getElementsByTagName('input');
for (const input of inputs) {
	input.addEventListener('change', go);
}
go();

document.querySelector('#output_bin').addEventListener('click', async (e) => {
	await navigator.clipboard.writeText(e.target.textContent);

	const output_msg = document.querySelector('#output_msg');
	const tmp = output_msg.textContent;
	output_msg.textContent = 'Copied!';
	setTimeout(() => output_msg.textContent = tmp, 2000);
});
