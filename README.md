# CSCE-3550-Project2
Rudimentary JWKS Server with SQLite DB Integration

# IMPORTANT
I used Visual Studio 2022 Community Edition for my project. The easiest method to open this project would be to download the repo and run the .sln file using Visual Studio. This ensures you have the correct package dependencies installed. In the gradebot, I am only getting a 50/65 as a result of the error message "No sources files found with SQL insertion parameters." However, my program is generating keys and inserting them into the SQLite database. Deepthi and I looked at it on Friday and were not sure why the gradebot wasn't able to see the SQL file with its' insertion parameters. Here is the method from the gradebot source code that returns that specific error message. 

	func CheckDatabaseQueryUsesParameters(c *Context) (Result, error) {
		result := Result{
			label:    "Database query uses parameters",
			awarded:  0,
			possible: 15,
		}

		if err := fs.WalkDir(os.DirFS(c.srcDir), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			b, err := os.ReadFile(filepath.Join(c.srcDir, p))
			if err != nil {
				return err
			}
			lines := bytes.Split(b, []byte("\n"))
			for i, line := range lines {
				if parameterizedInsertion.Match(line) {
					slog.Debug("Found SQL insertion query", slog.String("file", p), slog.Int("line", i+1))
					result.awarded = 15
					break
				}
			}
	
			return nil
		}); err != nil {
			return result, err
		}
		if result.awarded == 0 {
			result.message = "No sources files found with SQL insertion parameters"
		}
	
		return result, nil
	}


## Functionalities in Controller.cs

- **CreateJWKS()**: Generates a new JSON Web Key Set (JWKS) and stores it in the SQLite database.
- **RetrieveJWKS()**: Retrieves the existing JWKS from the SQLite database.
- **UpdateJWKS()**: Updates the existing JWKS in the SQLite database with a new set.
- **DeleteJWKS()**: Deletes the existing JWKS from the SQLite database.

These functionalities allow for the management of JWKS, ensuring secure communication by providing a way to sign and verify JSON Web Tokens (JWTs) using keys from the JWKS.


## Test Functionalities in UnitTest1.cs

- **AuthReturnsValidJWT()**: This test checks if the `Auth` method in the `ValuesController` returns a JWT (JSON Web Token) that is valid (i.e., its expiration date is in the future).

- **AuthReturnsInvalidJWT()**: This test verifies that the `Auth` method returns a JWT that is invalid (i.e., its expiration date is in the past).
