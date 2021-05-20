# JWT Middleware

Questa libreria contiene dei middleware per gin-gonic per la validare i token JWT

## Variabili di ambiente

| Nome Variabile | Descrizione | Valore di default |
|---|---|---|
|JWT_ACCESS_SECRET | Variabile obbligatoria con cui passare il secret con cui è stato firmato il token jwt| Non valorizzata |

## Middleware implmementati

I middleware attualmente implementati sono:

- DummyMiddleware - è una funzione che ritorna un handler che non effettua alcuna operazione
- JwtMiddleware - è una funzione che ritorna un handler che utilizzando l'access secret passato tramite la variabile di ambiente JWT_ACCESS_SECRET effettua la
  validazione della firma del JWT e ne controlla anche la scadenza. Alla fine della validazione sfrutta il context di
  gin-gonic ed inserisce nelle Keys del contesto (più o meno quelli che sono gli attributi della request in java) una
  entry con key ***userId*** in cui viene inserito il valore della claim ***id*** del token JWT
- StrapiCheckRoleMiddleware - è una funzione che ritorna un handler che utilizzando il client di strapi passato come
  parametro controlla che l'utente sia in un possesso di almeno uno dei ruoli passati come paramentro. Necessita che
  l'handler JwtMiddleware sia stato eseguito precedentemente perché utilizza la entry ***userId*** inserita nella mappa
  context.Keys di gin-gonic.