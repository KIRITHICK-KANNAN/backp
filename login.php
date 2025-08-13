<?php
include("/var/www/html/vfseu_mioot/globalAPIs/dataFilters/xss_filter.php");
include("/var/www/html/vfseu_mioot/globalAPIs/commonFn/utils.php");
include("/var/www/html/vfseu_mioot/globalAPIs/admin/v1/session.php");
//$ReqBody = json_decode(file_get_contents("php://input"),true);
//SessionValidator::check($ReqBody);
class Login {
	var $db;
	var $validator;
	var $max = 4;

    public function __construct($__con,$flag = false) {
		$this->db = new DBQuery($__con);
		$this->validator = new XSSFilter();
		if(!$flag) {
			if(!SessionValidator::check($__con,$this->validator)) {
				die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
			}
		}
    }
	
	public function adminLogin($rules=[],$messages=[]) {
		$data = json_decode(file_get_contents("php://input"),true);
		if(!$data || !count($data)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
		}
		extract($data);
		
		if(!count($rules)) {
			$rules = [
				'username' => 'required|alphanumeric|minLength:3|maxLength:25',
				'password' => 'required|passwordEncrypted|minLength:3|maxLength:50',
			];
		}
		
		$res = $this->validator->xssFilter($data,$rules,$messages);
		if(count($res)) {
			$user = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND user_status = 1 LIMIT 1",["user_name"=>$username]);
			if(count($user)) {
				$login_attempt = $user[0]["login_attempt"];
				if($login_attempt>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Account has been blocked"]));					
				}
				$login_attempt++;
				$user = $this->db->query("UPDATE admin_users SET login_attempt = :login_attempt,login_attempt_on = NOW() WHERE user_id = :user_id",["user_id"=>$user[0]["user_id"],"login_attempt"=>$login_attempt]);
			}
			die(json_encode(["status"=>2,"msg"=>"Invalid user22"]));
		}

		$res = $this->db->query("select encryption_key from admin_sessions where session_id=:session_id",["session_id"=>$session_id]);
		if(count($res)) {
			extract($res[0]);
		} else {
			die(json_encode(["status"=>6,"msg"=>"Invalid user33"]));
		}

		$password = Utils::decrypt($password,$encryption_key);
		$res = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND password = :password AND user_status = 1 LIMIT 1",["user_name"=>$username,"password"=>$password]);
		if(!count($res)) {
			$user = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND user_status = 1 LIMIT 1",["user_name"=>$username]);
			if(count($user)) {
				$login_attempt = $user[0]["login_attempt"];
				$login_attempt++;
				$user = $this->db->query("UPDATE admin_users SET login_attempt = :login_attempt,login_attempt_on = NOW() WHERE user_id = :user_id",["user_id"=>$user[0]["user_id"],"login_attempt"=>$login_attempt]);
				if($login_attempt>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Account has been blocked"]));					
				}
				die(json_encode(["status"=>3,"msg"=>"Invalid user2"]));
			}
			die(json_encode(["status"=>2,"msg"=>"Invalid user44"]));
		}

		extract($res[0]);
		if($login_attempt>=$this->max) {
			die(json_encode(["status"=>5,"msg"=>"Account has been blocked"]));
		}


		$_email_id = $email_id;
		if(!$_email_id || !trim($_email_id) || !filter_var($_email_id, FILTER_VALIDATE_EMAIL)) {
			die(json_encode(["status"=>2,"msg"=>"Mail does not exist"]));
		}
	
		$res = $this->db->query("UPDATE admin_sessions SET user_id = :user_id,role_id = :role_id WHERE session_id =:session_id",["user_id"=>$user_id,"role_id"=>$role_id,"session_id"=>$session_id]);

		$res = $this->db->query("SELECT * FROM admin_sessions WHERE user_id = :user_id AND login_status = 1",["user_id"=>$user_id]);
		if(count($res)) {
			//$res = $this->db->query("UPDATE admin_sessions SET login_status = 2 WHERE user_id =:user_id AND session_id !=:session_id",["user_id"=>$user_id,"session_id"=>$session_id]);
			if($res) {
				die(json_encode(["status"=>4,"msg"=>"Already login"]));
			}
		}

		$res = $this->db->query("UPDATE admin_users SET login_attempt = 0, login_attempt_on = NULL  WHERE user_id =:user_id",["user_id"=>$user_id]);
		$res = $this->db->find("SELECT session_token FROM admin_sessions WHERE session_id = :session_id",["session_id"=>$session_id]);

		if (!count($res)) {
			die(json_encode(["status"=>6,"msg"=>"Invalid token"]));
		} else {
			foreach($res as $row) {
				if($this->sendOTP($_email_id,$session_id)) {
					die(json_encode(["status"=>1,"session_id"=>$session_id,"session_token"=>$row["session_token"]]));
				} else {
					die(json_encode(["status"=>2,"msg"=>"Otp failed"]));
				}
			}
		}
	}

	public function logOut($data=[],$rules=[],$messages=[]) {
		//$data = json_decode(file_get_contents("php://input"),true);
		if(!$data || !count($data)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
		}
		if(isset($data["session_id"])) $data["Globalsessionid"] = $data["session_id"];
		if(isset($data["session_token"])) $data["Globalsessiontoken"] = $data["session_token"];
		extract($data);
		
		if(!count($rules)) {
			$rules = [
				'Globalsessionid' => 'required|numeric|minLength:1|maxLength:11',
				'Globalsessiontoken' => 'required|passwordEncrypted|minLength:3|maxLength:50',
			];
		}
		
		$res = $this->validator->xssFilter($data,$rules,$messages);
		if(count($res)) {
			return json_encode(["status"=>2,"msg"=>"Invalid session2"]);
		}
		
		$res = $this->db->find("SELECT * FROM admin_sessions WHERE  session_token =:session_token AND session_id=:session_id",["session_token"=>$Globalsessiontoken,"session_id"=>$Globalsessionid]);
		
		if(!count($res)) {
			return json_encode(["status"=>2,"msg"=>"Invalid session4"]);
		}
		extract($res[0]);
		
		$res = $this->db->query("UPDATE admin_sessions SET login_status = 2,last_ping=NOW() WHERE user_id =:user_id AND session_id = :session_id AND session_token =:session_token",["user_id"=>$user_id,"session_id"=>$Globalsessionid,"session_token"=>$Globalsessiontoken]);
		if($res) {
			return json_encode(["status"=>1,"msg"=>"Success"]);
		}
		return json_encode(["status"=>2,"msg"=>"Invalid session6"]);
	}
	
	public function adminReLogin($rules=[],$messages=[]) {
		$data = json_decode(file_get_contents("php://input"),true);
		if(!$data || !count($data)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
		}
		extract($data);
		
		if(!count($rules)) {
			$rules = [
				'username' => 'required|alphanumeric|minLength:3|maxLength:25',
				'password' => 'required|passwordEncrypted|minLength:3|maxLength:50',
			];
		}
		
		$res = $this->validator->xssFilter($data,$rules,$messages);
		if(count($res)) {
			$user = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND user_status = 1 LIMIT 1",["user_name"=>$username]);
			if(count($user)) {
				$login_attempt = $user[0]["login_attempt"];
				if($login_attempt>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Account has been blocked"]));					
				}
				$login_attempt++;
				$user = $this->db->query("UPDATE admin_users SET login_attempt = :login_attempt,login_attempt_on = NOW() WHERE user_id = :user_id",["user_id"=>$user[0]["user_id"],"login_attempt"=>$login_attempt]);
			}
			die(json_encode(["status"=>2,"msg"=>"Invalid user2"]));
		}

		$res = $this->db->query("select encryption_key from admin_sessions where session_id=:session_id",["session_id"=>$session_id]);
		if(count($res)) {
			extract($res[0]);
		} else {
			die(json_encode(["status"=>6,"msg"=>"Invalid user4"]));
		}

		$password = Utils::decrypt($password,$encryption_key);
		$res = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND password = :password AND user_status = 1 LIMIT 1",["user_name"=>$username,"password"=>$password]);
		if(!count($res)) {
			$user = $this->db->find("SELECT * FROM admin_users WHERE user_name = :user_name AND user_status = 1 LIMIT 1",["user_name"=>$username]);
			if(count($user)) {
				$login_attempt = $user[0]["login_attempt"];
				$login_attempt++;
				$user = $this->db->query("UPDATE admin_users SET login_attempt = :login_attempt,login_attempt_on = NOW() WHERE user_id = :user_id",["user_id"=>$user[0]["user_id"],"login_attempt"=>$login_attempt]);
				if($login_attempt>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Account has been blocked"]));					
				}
				die(json_encode(["status"=>3,"msg"=>"Invalid user2"]));
			}
			die(json_encode(["status"=>2,"msg"=>"Invalid user6"]));
		}
		extract($res[0]);
		$_email_id = $email_id;
		if(!$_email_id || !trim($_email_id) || !filter_var($_email_id, FILTER_VALIDATE_EMAIL)) {
			die(json_encode(["status"=>2,"msg"=>"Mail does not exist"]));
		}
		
		$res = $this->db->query("UPDATE admin_sessions SET user_id = :user_id,role_id = :role_id WHERE session_id =:session_id",["user_id"=>$user_id,"role_id"=>$role_id,"session_id"=>$session_id]);
		$res = $this->db->query("UPDATE admin_sessions SET login_status = 2 WHERE user_id =:user_id AND session_id !=:session_id",["user_id"=>$user_id,"session_id"=>$session_id]);
		$res = $this->db->query("UPDATE admin_users SET login_attempt = 0, login_attempt_on = NULL  WHERE user_id =:user_id",["user_id"=>$user_id]);

		$res = $this->db->query("UPDATE admin_sessions SET login_status = 1 WHERE user_id =:user_id AND session_id = :session_id",["user_id"=>$user_id,"session_id"=>$session_id]);

		$res = $this->db->find("SELECT session_token FROM admin_sessions WHERE session_id = :session_id AND login_status = 1",["session_id"=>$session_id]);

		if (!count($res)) {
			die(json_encode(["status"=>6,"msg"=>"Invalid token"]));
		} else {
			foreach($res as $row) {
				if($this->sendOTP($_email_id,$session_id)) {
					die(json_encode(["status"=>1,"session_id"=>$session_id,"session_token"=>$row["session_token"]]));
				} else {
					die(json_encode(["status"=>2,"msg"=>"Mail error"]));
				}
				
			}
		}
	}
	
	public function adminPing($rules=[],$messages=[]) {
		$data = json_decode(file_get_contents("php://input"),true);
		if(!$data || !count($data)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
		}
		extract($data);
		
		if(!count($rules)) {
			$rules = [
				'type' => 'required|numeric|minLength:1|maxLength:1',
				'activity_time' => 'required|isDatetime|minLength:16|maxLength:19',
			];
		}
		$res = $this->validator->xssFilter($data,$rules,$messages);
		if(count($res)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid user"]));
		}

		$res = $this->db->query("SELECT ass.role_id,ass.user_id,ad.full_name FROM admin_sessions ass LEFT JOIN admin_users ad ON ass.user_id=ad.user_id WHERE ass.session_token =:session_token AND ass.session_id=:session_id AND ad.user_status=1",["session_id"=>$session_id,"session_token"=>$session_token]);
		
		if(!count($res)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid user"]));
		}
		
		$res = $this->db->query("UPDATE admin_sessions SET last_activity_on=:activity_time,last_ping=NOW() WHERE session_id =:session_id AND session_token =:session_token",["activity_time"=>$activity_time,"session_id"=>$session_id,"session_token"=>$session_token]);
		
		$res = $this->db->query("SELECT * FROM admin_sessions WHERE session_id =:session_id AND session_token =:session_token  AND login_status=1 AND last_activity_on IS NOT NULL AND last_activity_on >= NOW() - INTERVAL 30 MINUTE",["session_id"=>$session_id,"session_token"=>$session_token]);
		
        if(!count($res)){
            $res = $this->db->query("UPDATE admin_sessions SET  login_status = 2  WHERE session_id = :session_id AND session_token =:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
			die(json_encode(["status"=>4,"msg"=>"error"]));
        }
		die(json_encode(["status"=>1,"updated_activity_time"=>$activity_time,"msg"=>"success"]));
	}
	
	public function validiateOTP($rules=[],$messages=[]) {
		$data = json_decode(file_get_contents("php://input"),true);
		if(!$data || !count($data)) {
			die(json_encode(["status"=>2,"msg"=>"Invalid credential"]));
		}
		extract($data);
		
		if(!count($rules)) {
			$rules = [
				'otp_number' => 'required|numeric|minLength:1|maxLength:6',
			];
		}
		$res = $this->validator->xssFilter($data,$rules,$messages);
		if(count($res)) {
			$_res = $this->db->query("select * from admin_sessions WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
			if(count($_res)) {
				$_otp_attempts = $_res[0]["otp_attempts"];
				$_otp_attempts++;
				$res = $this->db->query("UPDATE admin_sessions SET otp_attempts=otp_attempts+1 WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
				if($_otp_attempts>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Locked"]));
				}
			}
			die(json_encode(["status"=>3,"msg"=>"Invalid otp"]));
		}
		
		$res = $this->db->query("select * from admin_sessions where otp_number=:otp_number and session_id=:session_id and session_token=:session_token",["otp_number"=>$otp_number,"session_id"=>$session_id,"session_token"=>$session_token]);
		
		if(!count($res)) {
			/*
			$res = $this->db->query("UPDATE admin_sessions SET otp_attempts=otp_attempts+1 WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
			$_res = $this->db->query("select * from admin_sessions WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
			if(count($_res)) {
				$_otp_attempts = $_res[0]["otp_attempts"];
				if($_otp_attempts>=3) {
					die(json_encode(["status"=>5,"msg"=>"Locked"]));
				}
			}
			die(json_encode(["status"=>3,"msg"=>"Invalid otppp"]));
			*/
			$_res = $this->db->query("select * from admin_sessions WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
			if(count($_res)) {
				$_otp_attempts = $_res[0]["otp_attempts"];
				$_otp_attempts++;
				$_res = $this->db->query("UPDATE admin_sessions SET otp_attempts=otp_attempts+1 WHERE session_id=:session_id OR session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
				if($_otp_attempts>=$this->max) {
					die(json_encode(["status"=>5,"msg"=>"Locked"]));
				}
				die(json_encode(["status"=>3,"msg"=>"Invalid otp"]));
			}
		}
		/*		
		$res = $this->db->query("select * from admin_sessions where session_id=:session_id and session_token=:session_token AND otp_number=:otp_number",["session_id"=>$session_id,"session_token"=>$session_token,"otp_number"=>$otp_number]);
		if(!count($res)) {
			die(json_encode(["status"=>4,"msg"=>"Expired"]));
		}
		*/
		extract($res[0]);
		$otp_attempts++;
		$otpRes = $this->db->query("UPDATE admin_sessions SET otp_attempts=otp_attempts+1 WHERE session_id=:session_id and session_token=:session_token",["session_id"=>$session_id,"session_token"=>$session_token]);
		if($otp_attempts>$this->max) {
			die(json_encode(["status"=>5,"msg"=>"Locked"]));
		}
		
		$res = $this->db->query("select * from admin_sessions where session_id=:session_id and session_token=:session_token and otp_number=:otp_number and otp_expired_on IS NOT NULL AND otp_expired_on >= NOW() - INTERVAL 5 MINUTE",["session_id"=>$session_id,"session_token"=>$session_token,"otp_number"=>$otp_number]);
		if(!count($res)) {
			die(json_encode(["status"=>6,"msg"=>"Expired"]));
		}

		extract($res[0]);
		$res = $this->db->query("UPDATE admin_sessions SET login_status = 1 WHERE session_id = :session_id",["session_id"=>$session_id]);
		die(json_encode(["status"=>1,"msg"=>"success"]));
	}
	
	public function sendOTP($toEmail,$session_id) {
		$query = "Select * from email_templates where template_id=:template_id order by template_id asc limit 1";
		$res = $this->db->query($query,["template_id"=>1]);
		//echo "<pre>"; print_r($res);exit;
		extract($res[0]);
		
		$otp_number = rand(100000, 999999);
		$mail_body=str_replace("{OTP}",trim($otp_number),trim($mail_body));
		
		$res = $this->db->query("UPDATE admin_sessions SET otp_number=:otp_number,otp_expired_on=Now() WHERE session_id=:session_id",["otp_number"=>$otp_number,"session_id"=>$session_id]);
		return Utils::sendMail($toEmail,$mail_subject,$mail_body,$mail_from);
	}
	
}
?>