const botonGenerar = document.getElementById('generarClaves');
const botonFirmar = document.getElementById('firmarMensaje');
const botonCifrar = document.getElementById('cifrarMensaje');
const botonDescifrar = document.getElementById('descifrarMensaje');

const clavePublica = document.getElementById('clavePublica');
const clavePrivada = document.getElementById('clavePrivada');
const claveRemota = document.getElementById('claveRemota');
const mensaje = document.getElementById('mensaje');
const mensajeCifrado = document.getElementById('mensajeCifrado');
const mensajeRecibido = document.getElementById('mensajeRecibido');
const resultado = document.getElementById('resultado');
const estadoFirma = document.getElementById('estadoFirma');

let claves = null;
let clavesCifrado = null;
let clavesRemotas = null;

botonGenerar.addEventListener('click', async function() {

    claves = await crypto.subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    );

    clavesCifrado = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['encrypt', 'decrypt']
    );

    const publica = await crypto.subtle.exportKey('spki', claves.publicKey);
    const privada = await crypto.subtle.exportKey('pkcs8', claves.privateKey);

    const publicaCifrado = await crypto.subtle.exportKey('spki', clavesCifrado.publicKey);
    const privadaCifrado = await crypto.subtle.exportKey('pkcs8', clavesCifrado.privateKey);

    clavePublica.value = JSON.stringify({
        firma: convertirBase64(publica),
        cifrado: convertirBase64(publicaCifrado)
    }, null, 4);

    clavePrivada.value = JSON.stringify({
        firma: convertirBase64(privada),
        cifrado: convertirBase64(privadaCifrado)
    }, null, 4);

    clavesRemotas = null;
    mensajeCifrado.value = '';

});

function convertirBase64(datos) {
    return btoa(String.fromCharCode(...new Uint8Array(datos)));
}

async function importarClavePublica(clave, algoritmo, usos) {

    const datos = Uint8Array.from(atob(clave), function(c) {
        return c.charCodeAt(0);
    });

    return await crypto.subtle.importKey(
        'spki',
        datos,
        algoritmo,
        true,
        usos
    );
}

async function importarClavesRemotas() {

    const datos = JSON.parse(claveRemota.value);

    const firma = await importarClavePublica(
        datos.firma,
        {
            name: 'RSA-PSS',
            hash: 'SHA-256'
        },
        ['verify']
    );

    const cifrado = await importarClavePublica(
        datos.cifrado,
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
        },
        ['encrypt']
    );

    clavesRemotas = {
        firma: firma,
        cifrado: cifrado
    };
}

botonFirmar.addEventListener('click', async function() {

    try {

        if (claves === null) {
            alert('Primero genera tus claves');
            return;
        }

        const texto = mensaje.value;

        if (texto === '') {
            alert('Escribe un mensaje');
            return;
        }

        const datos = new TextEncoder().encode(texto);

        const firma = await crypto.subtle.sign(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            claves.privateKey,
            datos
        );

        const objeto = {
            missatge: texto,
            signatura: convertirBase64(firma)
        };

        mensaje.value = JSON.stringify(objeto, null, 4);

    } catch (error) {
        alert('Error al firmar el mensaje');
        console.log(error);
    }

});

botonCifrar.addEventListener('click', async function() {

    try {

        if (claves === null) {
            alert('Primero genera tus claves');
            return;
        }

        await importarClavesRemotas();

        const objeto = JSON.parse(mensaje.value);
        const datos = new TextEncoder().encode(JSON.stringify(objeto));

        const claveAES = await crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));

        const textoCifrado = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            claveAES,
            datos
        );

        const claveAESExportada = await crypto.subtle.exportKey('raw', claveAES);

        const claveAESCifrada = await crypto.subtle.encrypt(
            {
                name: 'RSA-OAEP'
            },
            clavesRemotas.cifrado,
            claveAESExportada
        );

        const resultadoCifrado = {
            clave: convertirBase64(claveAESCifrada),
            iv: convertirBase64(iv),
            datos: convertirBase64(textoCifrado)
        };

        mensajeCifrado.value = JSON.stringify(resultadoCifrado, null, 4);

    } catch (error) {
        alert('Error al cifrar. Comprueba las claves y que hayas firmado el mensaje.');
        console.log(error);
    }

});

botonDescifrar.addEventListener('click', async function() {

    try {

        if (claves === null) {
            alert('Primero genera tus claves');
            return;
        }

        await importarClavesRemotas();

        const paquete = JSON.parse(mensajeRecibido.value);

        const claveAES = await crypto.subtle.decrypt(
            {
                name: 'RSA-OAEP'
            },
            clavesCifrado.privateKey,
            Uint8Array.from(atob(paquete.clave), c => c.charCodeAt(0))
        );

        const claveImportada = await crypto.subtle.importKey(
            'raw',
            claveAES,
            'AES-GCM',
            false,
            ['decrypt']
        );

        const datosDescifrados = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: Uint8Array.from(atob(paquete.iv), c => c.charCodeAt(0))
            },
            claveImportada,
            Uint8Array.from(atob(paquete.datos), c => c.charCodeAt(0))
        );

        const objeto = JSON.parse(new TextDecoder().decode(datosDescifrados));

        resultado.value = objeto.missatge;

        const firma = Uint8Array.from(atob(objeto.signatura), c => c.charCodeAt(0));
        const datos = new TextEncoder().encode(objeto.missatge);

        const firmaValida = await crypto.subtle.verify(
            {
                name: 'RSA-PSS',
                saltLength: 32
            },
            clavesRemotas.firma,
            firma,
            datos
        );

        if (firmaValida) {
            estadoFirma.textContent = 'La firma es válida. El mensaje no ha sido modificado.';
            estadoFirma.style.color = 'green';
        } else {
            estadoFirma.textContent = 'La firma no es válida. El mensaje ha sido modificado.';
            estadoFirma.style.color = 'red';
        }

    } catch (error) {
        alert('No se ha podido descifrar el mensaje. Comprueba las claves.');
        console.log(error);
    }

});