package willydekeyser.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "authorization")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Authorization {

	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getRegisteredClientId() {
		return registeredClientId;
	}
	public void setRegisteredClientId(String registeredClientId) {
		this.registeredClientId = registeredClientId;
	}
	public String getPrincipalName() {
		return principalName;
	}
	public void setPrincipalName(String principalName) {
		this.principalName = principalName;
	}
	public String getAuthorizationGrantType() {
		return authorizationGrantType;
	}
	public void setAuthorizationGrantType(String authorizationGrantType) {
		this.authorizationGrantType = authorizationGrantType;
	}
	public String getAuthorizedScopes() {
		return authorizedScopes;
	}
	public void setAuthorizedScopes(String authorizedScopes) {
		this.authorizedScopes = authorizedScopes;
	}
	public String getAttributes() {
		return attributes;
	}
	public void setAttributes(String attributes) {
		this.attributes = attributes;
	}
	public String getState() {
		return state;
	}
	public void setState(String state) {
		this.state = state;
	}
	public String getAuthorizationCodeValue() {
		return authorizationCodeValue;
	}
	public void setAuthorizationCodeValue(String authorizationCodeValue) {
		this.authorizationCodeValue = authorizationCodeValue;
	}
	public Instant getAuthorizationCodeIssuedAt() {
		return authorizationCodeIssuedAt;
	}
	public void setAuthorizationCodeIssuedAt(Instant authorizationCodeIssuedAt) {
		this.authorizationCodeIssuedAt = authorizationCodeIssuedAt;
	}
	public Instant getAuthorizationCodeExpiresAt() {
		return authorizationCodeExpiresAt;
	}
	public void setAuthorizationCodeExpiresAt(Instant authorizationCodeExpiresAt) {
		this.authorizationCodeExpiresAt = authorizationCodeExpiresAt;
	}
	public String getAuthorizationCodeMetadata() {
		return authorizationCodeMetadata;
	}
	public void setAuthorizationCodeMetadata(String authorizationCodeMetadata) {
		this.authorizationCodeMetadata = authorizationCodeMetadata;
	}
	public String getAccessTokenValue() {
		return accessTokenValue;
	}
	public void setAccessTokenValue(String accessTokenValue) {
		this.accessTokenValue = accessTokenValue;
	}
	public Instant getAccessTokenIssuedAt() {
		return accessTokenIssuedAt;
	}
	public void setAccessTokenIssuedAt(Instant accessTokenIssuedAt) {
		this.accessTokenIssuedAt = accessTokenIssuedAt;
	}
	public Instant getAccessTokenExpiresAt() {
		return accessTokenExpiresAt;
	}
	public void setAccessTokenExpiresAt(Instant accessTokenExpiresAt) {
		this.accessTokenExpiresAt = accessTokenExpiresAt;
	}
	public String getAccessTokenMetadata() {
		return accessTokenMetadata;
	}
	public void setAccessTokenMetadata(String accessTokenMetadata) {
		this.accessTokenMetadata = accessTokenMetadata;
	}
	public String getAccessTokenType() {
		return accessTokenType;
	}
	public void setAccessTokenType(String accessTokenType) {
		this.accessTokenType = accessTokenType;
	}
	public String getAccessTokenScopes() {
		return accessTokenScopes;
	}
	public void setAccessTokenScopes(String accessTokenScopes) {
		this.accessTokenScopes = accessTokenScopes;
	}
	public String getRefreshTokenValue() {
		return refreshTokenValue;
	}
	public void setRefreshTokenValue(String refreshTokenValue) {
		this.refreshTokenValue = refreshTokenValue;
	}
	public Instant getRefreshTokenIssuedAt() {
		return refreshTokenIssuedAt;
	}
	public void setRefreshTokenIssuedAt(Instant refreshTokenIssuedAt) {
		this.refreshTokenIssuedAt = refreshTokenIssuedAt;
	}
	public Instant getRefreshTokenExpiresAt() {
		return refreshTokenExpiresAt;
	}
	public void setRefreshTokenExpiresAt(Instant refreshTokenExpiresAt) {
		this.refreshTokenExpiresAt = refreshTokenExpiresAt;
	}
	public String getRefreshTokenMetadata() {
		return refreshTokenMetadata;
	}
	public void setRefreshTokenMetadata(String refreshTokenMetadata) {
		this.refreshTokenMetadata = refreshTokenMetadata;
	}
	public String getOidcIdTokenValue() {
		return oidcIdTokenValue;
	}
	public void setOidcIdTokenValue(String oidcIdTokenValue) {
		this.oidcIdTokenValue = oidcIdTokenValue;
	}
	public Instant getOidcIdTokenIssuedAt() {
		return oidcIdTokenIssuedAt;
	}
	public void setOidcIdTokenIssuedAt(Instant oidcIdTokenIssuedAt) {
		this.oidcIdTokenIssuedAt = oidcIdTokenIssuedAt;
	}
	public Instant getOidcIdTokenExpiresAt() {
		return oidcIdTokenExpiresAt;
	}
	public void setOidcIdTokenExpiresAt(Instant oidcIdTokenExpiresAt) {
		this.oidcIdTokenExpiresAt = oidcIdTokenExpiresAt;
	}
	public String getOidcIdTokenMetadata() {
		return oidcIdTokenMetadata;
	}
	public void setOidcIdTokenMetadata(String oidcIdTokenMetadata) {
		this.oidcIdTokenMetadata = oidcIdTokenMetadata;
	}
	public String getOidcIdTokenClaims() {
		return oidcIdTokenClaims;
	}
	public void setOidcIdTokenClaims(String oidcIdTokenClaims) {
		this.oidcIdTokenClaims = oidcIdTokenClaims;
	}
	@Id
	@Column
	private String id;
	private String registeredClientId;
	private String principalName;
	private String authorizationGrantType;
	@Column(length = 1000)
	private String authorizedScopes;
	@Lob
	@Column(length = 4000)
	private String attributes;
	@Column(length = 500)
	private String state;
	@Lob
	@Column(length = 4000)
	private String authorizationCodeValue;
	private Instant authorizationCodeIssuedAt;
	private Instant authorizationCodeExpiresAt;
	private String authorizationCodeMetadata;
	@Lob
	@Column(length = 4000)
	private String accessTokenValue;
	private Instant accessTokenIssuedAt;
	private Instant accessTokenExpiresAt;
	@Lob
	@Column(length = 2000)
	private String accessTokenMetadata;
	private String accessTokenType;
	@Column(length = 1000)
	private String accessTokenScopes;
	@Lob
	@Column(length = 4000)
	private String refreshTokenValue;
	private Instant refreshTokenIssuedAt;
	private Instant refreshTokenExpiresAt;
	@Lob
	@Column(length = 2000)
	private String refreshTokenMetadata;
	@Lob
	@Column(length = 4000)
	private String oidcIdTokenValue;
	private Instant oidcIdTokenIssuedAt;
	private Instant oidcIdTokenExpiresAt;
	@Lob
	@Column(length = 2000)
	private String oidcIdTokenMetadata;
	@Lob
	@Column(length = 2000)
	private String oidcIdTokenClaims;
}