<?php
class AuthController {
  public function register() {
    global $conn;

    $response = array();

    $full_name = $_POST['full_name'] ?? '';
    $user_id = rand(000000, 999999);
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($full_name)) {
      $response['status'] = 'error';
      $response['message'] = 'Full Name is required.';
      echo json_encode($response);
      return;
    }

    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email is required.';
      echo json_encode($response);
      return;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format.';
      echo json_encode($response);
      return;
    }

    if (empty($password)) {
      $response['status'] = 'error';
      $response['message'] = 'Password is required.';
      echo json_encode($response);
      return;
    } elseif (strlen($password) < 6) {
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long.';
      echo json_encode($response);
      return;
    }

    if (empty($confirm_password)) {
      $response['status'] = 'error';
      $response['message'] = 'Confirm Password is required.';
      echo json_encode($response);
      return;
    } elseif ($password !== $confirm_password) {
      $response['status'] = 'error';
      $response['message'] = 'Passwords do not match.';
      echo json_encode($response);
      return;
    }

    // Check if email already exists
    $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();

    if($result->num_rows > 0){
      $response['status'] = 'error';
      $response['message'] = 'Email already exists.';
      echo json_encode($response);
      return;
    }

    // Hash the password before inserting in the database
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Insert user into the database
    $stmt = $conn->prepare("INSERT INTO users (user_id, full_name, email, password) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("ssss", $user_id, $full_name, $email, $hashed_password);

    if($stmt->execute()){
      $response['status'] = 'success';
      $response['message'] = 'User registered successfully.';
      echo json_encode($response);
      return;
    } else {
      $response['status'] = 'error';
      $response['message'] = 'Error registering user: ' . $conn->error;
      echo json_encode($response);
      return;
    }

    $stmt->close();
  }

  public function login() {
    global $conn;
  
    $response = array();
  
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
  
    if (empty($email)) {
      $response['status'] = 'error';
      $response['message'] = 'Email is required.';
      echo json_encode($response);
      return;
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
      $response['status'] = 'error';
      $response['message'] = 'Invalid email format.';
      echo json_encode($response);
      return;
    }
  
    if (empty($password)) {
      $response['error'] = 'Password is required.';
      echo json_encode($response);
      return;
    } elseif (strlen($password) < 6) {
      $response['status'] = 'error';
      $response['message'] = 'Password must be at least 6 characters long.';
      echo json_encode($response);
      return;
    }
  
    // Retrieve user from database by email
    $stmt = $conn->prepare("SELECT user_id, full_name, email, created_at, image, password FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $stmt->close();
  
    if($result->num_rows == 0){
      $response['error'] = 'User not found.';
      echo json_encode($response);
      return;
    }
  
    $user = $result->fetch_assoc();
  
    // Verify password
    if(!password_verify($password, $user['password'])){
      $response['error'] = 'Invalid email or password.';
      echo json_encode($response);
    }
    else {
      unset($user['password']);
      $response['success'] = 'Login successful.';
      $response['message'] = True;
      $response['user'] = $user;
      echo json_encode($response);
    }
  }
}
?>