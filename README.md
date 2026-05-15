# Week 2: Implementing Security Measures in OWASP Juice Shop

## Objective of Task
- Apply input validation and sanitization
- Add password hashing and authentication security
- Secure the application against XSS attacks

---

# 1. Backend Fixes (`login.ts`)

## Step A: Cleaning User Input

We use the `validator` library to:
- Remove extra spaces
- Escape dangerous characters
- Validate email format
- Enforce password length

```ts
email = validator.trim(email || '')
email = validator.escape(email)

if (!validator.isEmail(email)) {
  return res.status(400).json({
    error: 'Invalid email format'
  })
}

if (!validator.isLength(password || '', { min: 5 })) {
  return res.status(400).json({
    error: 'Password too short'
  })
}
```

---

## Step B: Safe Database Searching

We use Sequelize replacements to prevent SQL Injection attacks.

```ts
const authenticatedUser = await models.sequelize.query(
  `SELECT * FROM Users
   WHERE email = :email
   AND deletedAt IS NULL`,
  {
    replacements: { email },
    model: UserModel,
    plain: true
  }
)
```

---

# 2. Password & Login Security

## Step A: Password Verification with bcrypt

Instead of comparing plain passwords, we use `bcrypt.compare()` to safely verify the hashed password.

```ts
const bcrypt = require('bcrypt')

const isPasswordValid = await bcrypt.compare(
  password,
  user.data.password
)

if (!isPasswordValid) {
  return res.status(401).send('Invalid email or password')
}
```

---

## Step B: JWT Authentication Token

After successful login, a JWT token is generated that expires in 1 hour.

```ts
const jwt = require('jsonwebtoken')

const token = jwt.sign(
  {
    id: user.data.id,
    email: user.data.email
  },
  'your-secret-key',
  { expiresIn: '1h' }
)
```

---

# 3. Automatic Password Hashing (`user.ts`)

A Sequelize hook automatically hashes passwords whenever a user updates their password.

---

## Replace This Vulnerable Code

```ts
password: {
  type: DataTypes.STRING,
  set (clearTextPassword: string) {
    this.setDataValue(
      'password',
      security.hash(clearTextPassword)
    )
  }
},
```

---

## Replace With This Secure Code

```ts
password: {
  type: DataTypes.STRING
},
```

---

## Add This Before

```ts
export { User as UserModel, UserModelInit }
```

---

## Secure Hooks Code

```ts
User.addHook('beforeUpdate', async (user: User) => {
  if (user.changed('password')) {
    user.password = await bcrypt.hash(user.password, 10)
  }
})

User.addHook('afterValidate', async (user: User) => {
  if (
    user.email &&
    user.email.toLowerCase() ===
      `acc0unt4nt@${config.get<string>('application.domain')}`.toLowerCase()
  ) {
    await Promise.reject(
      new Error(
        'Nice try, but this is not how the "Ephemeral Accountant" challenge works!'
      )
    )
  }
})
```

---

# 4. Secure Login Route (`login.ts`)

## Vulnerable Code

```ts
return (req: Request, res: Response, next: NextFunction) => {

  // verifyPreLoginChallenges(req)

  // models.sequelize.query(
  // `SELECT * FROM Users WHERE email = '${req.body.email || ''}'
  // AND password = '${security.hash(req.body.password || '')}'
  // AND deletedAt IS NULL`,
  // { model: UserModel, plain: true })

  // .then((authenticatedUser) => {

  // const user = utils.queryResultToJson(authenticatedUser)

  // if (user.data?.id && user.data.totpSecret !== '') {

  // res.status(401).json({
  // status: 'totp_token_required',
  // data: {
  // tmpToken: security.authorize({
  // userId: user.data.id,
  // type: 'password_valid_needs_second_factor_token'
  // })
  // }
  // })

  // } else if (user.data?.id) {

  // afterLogin(user, res, next)

  // } else {

  // res.status(401).send(res.__('Invalid email or password.'))

  // }

  // }).catch((error: Error) => {
  // next(error)
  // })
}
```

---

## Replace With This Secure Code

```ts
return async (req: Request, res: Response, next: NextFunction) => {

  verifyPreLoginChallenges(req)

  let { email, password } = req.body

  email = validator.trim(email || '')
  email = validator.escape(email)

  if (!validator.isEmail(email)) {
    return res.status(400).json({
      error: 'Invalid email format'
    })
  }

  if (!validator.isLength(password || '', { min: 5 })) {
    return res.status(400).json({
      error: 'Password too short'
    })
  }

  try {

    const authenticatedUser = await models.sequelize.query(
      `SELECT * FROM Users
       WHERE email = :email
       AND deletedAt IS NULL`,
      {
        replacements: { email },
        model: UserModel,
        plain: true
      }
    )

    const user = utils.queryResultToJson(authenticatedUser)

    if (!user.data) {
      return res.status(401).send(
        'Invalid email or password'
      )
    }

    const bcrypt = require('bcrypt')

    const isPasswordValid = await bcrypt.compare(
      password,
      user.data.password
    )

    if (!isPasswordValid) {
      return res.status(401).send(
        'Invalid email or password'
      )
    }

    if (
      user.data.totpSecret &&
      user.data.totpSecret !== ''
    ) {
      return res.status(401).json({
        status: 'totp_token_required',
        data: {
          tmpToken: security.authorize({
            userId: user.data.id,
            type:
              'password_valid_needs_second_factor_token'
          })
        }
      })
    }

    const jwt = require('jsonwebtoken')

    const token = jwt.sign(
      {
        id: user.data.id,
        email: user.data.email
      },
      'your-secret-key',
      { expiresIn: '1h' }
    )

    return res.json({
      authentication: {
        token: token,
        bid: user.data.id,
        umail: user.data.email
      }
    })

  } catch (error) {
    next(error)
  }
}
```

---

# 5. Helmet Security Middleware (`server.ts`)

Helmet protects the application from:
- XSS attacks
- Clickjacking
- MIME sniffing
- Content injection

## Add This Code

```ts
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"]
      }
    }
  })
)
```

## Place It Between

```ts
const app = express()
```

and

```ts
const server = new http.Server(app)
```

---

# 6. Frontend Security Fixes (`search-result.component.ts`)

## Fixing Description XSS

### Replace This Vulnerable Code

```ts
tableData[i].description =
this.sanitizer.bypassSecurityTrustHtml(
  tableData[i].description
)
```

### With This Secure Code

```ts
tableData[i].description =
this.sanitizer.sanitize(
  1,
  tableData[i].description
)
```

---

## Fixing Search Bar XSS

### Replace This Vulnerable Code

```ts
this.searchValue =
this.sanitizer.bypassSecurityTrustHtml(queryParam)
```

### With This Secure Code

```ts
this.searchValue = queryParam
```

---

# Required Packages

Install these dependencies:

```bash
npm install validator bcrypt jsonwebtoken helmet
```

---

# Security Improvements Achieved

| Security Issue | Solution Applied |
|---|---|
| SQL Injection | Sequelize replacements |
| Weak Password Handling | bcrypt hashing |
| Unsafe Authentication | JWT token security |
| XSS Attacks | Angular sanitization |
| Unsafe Headers | Helmet middleware |
| Input Validation | validator library |
| Password Exposure | Automatic hashing hooks |

---

# Final Outcome

After implementing these fixes, the application becomes more secure against:
- SQL Injection
- Cross-Site Scripting (XSS)
- Weak password attacks
- Authentication bypass attempts
- Unsafe HTTP header exploits

The login system now follows secure authentication and validation practices used in modern web applications.
