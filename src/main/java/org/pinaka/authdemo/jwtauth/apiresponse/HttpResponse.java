package org.pinaka.authdemo.jwtauth.apiresponse;

import org.springframework.http.HttpStatus;

public class HttpResponse {

	private int httpStatusCode;
	private HttpStatus httpStatus;
	private String message;
	private String reason;
	
	public HttpResponse(int httpStatusCode, HttpStatus httpStatus, String message, String reason) {
		super();
		this.httpStatusCode = httpStatusCode;
		this.httpStatus = httpStatus;
		this.message = message;
		this.reason = reason;
	}
	public int getHttpStatusCode() {
		return httpStatusCode;
	}
	public void setHttpStatusCode(int httpStatusCode) {
		this.httpStatusCode = httpStatusCode;
	}
	public HttpStatus getHttpStatus() {
		return httpStatus;
	}
	public void setHttpStatus(HttpStatus httpStatus) {
		this.httpStatus = httpStatus;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	public String getReason() {
		return reason;
	}
	public void setReason(String reason) {
		this.reason = reason;
	}
	
}
