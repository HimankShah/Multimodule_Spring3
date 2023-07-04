package willydekeyser.entity;

import java.time.Instant;


import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Builder;

@Entity
@Builder
public class RefreshToken {

	
	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String token;
    private Instant expiryAt;
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public Instant getExpiryAt() {
		return expiryAt;
	}
	public void setExpiryAt(Instant expiryAt) {
		this.expiryAt = expiryAt;
	}
	public RefreshToken(String token, Instant expiryAt) {
		super();
		this.token = token;
		this.expiryAt = expiryAt;
	}
	
    


	
	
}
